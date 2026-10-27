package com.alumni.management.verification.service;

import com.alumni.management.verification.dto.FirebaseTokenClaims;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class FirebaseTokenService {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseTokenService.class);
    private static final String GOOGLE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

    @Value("${firebase.project-id:alumni-connect-80612}")
    private String projectId;

    @Value("${firebase.service-account.path:}")
    private String serviceAccountPath;

    private boolean firebaseAdminInitialized = false;
    private final Gson gson = new Gson();
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    // Cache of public certificates: Key ID (kid) -> X509Certificate
    private final Map<String, X509Certificate> certCache = new ConcurrentHashMap<>();
    private Instant certCacheExpiry = Instant.MIN;

    @PostConstruct
    public void init() {
        if (!FirebaseApp.getApps().isEmpty()) {
            firebaseAdminInitialized = true;
            logger.info("FirebaseApp is already initialized with name: {}", FirebaseApp.getInstance().getName());
            return;
        }

        try {
            InputStream serviceAccountStream = null;

            // 1. Check configured service account path
            if (serviceAccountPath != null && !serviceAccountPath.trim().isEmpty()) {
                File file = new File(serviceAccountPath.trim());
                if (file.exists()) {
                    serviceAccountStream = new FileInputStream(file);
                    logger.info("Loading Firebase credentials from configured path: {}", file.getAbsolutePath());
                }
            }

            // 2. Check GOOGLE_APPLICATION_CREDENTIALS env var
            if (serviceAccountStream == null) {
                String envPath = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
                if (envPath != null && !envPath.trim().isEmpty()) {
                    File file = new File(envPath.trim());
                    if (file.exists()) {
                        serviceAccountStream = new FileInputStream(file);
                        logger.info("Loading Firebase credentials from GOOGLE_APPLICATION_CREDENTIALS: {}", file.getAbsolutePath());
                    }
                }
            }

            // 3. Check FIREBASE_CONFIG env var
            if (serviceAccountStream == null) {
                String firebaseConfig = System.getenv("FIREBASE_CONFIG");
                if (firebaseConfig != null && !firebaseConfig.trim().isEmpty()) {
                    if (firebaseConfig.trim().startsWith("{")) {
                        serviceAccountStream = new ByteArrayInputStream(firebaseConfig.getBytes(StandardCharsets.UTF_8));
                        logger.info("Loading Firebase credentials from FIREBASE_CONFIG JSON environment variable");
                    } else {
                        File file = new File(firebaseConfig.trim());
                        if (file.exists()) {
                            serviceAccountStream = new FileInputStream(file);
                            logger.info("Loading Firebase credentials from FIREBASE_CONFIG path: {}", file.getAbsolutePath());
                        }
                    }
                }
            }

            GoogleCredentials credentials;
            if (serviceAccountStream != null) {
                credentials = GoogleCredentials.fromStream(serviceAccountStream);
            } else {
                // Try Application Default Credentials (ADC)
                try {
                    credentials = GoogleCredentials.getApplicationDefault();
                    logger.info("Loaded Firebase credentials from Application Default Credentials");
                } catch (Exception adcEx) {
                    logger.info("No service account credentials file found (ADC unavailable: {}). Token verification will use Google's official public keys.", adcEx.getMessage());
                    credentials = null;
                }
            }

            if (credentials != null) {
                FirebaseOptions options = FirebaseOptions.builder()
                        .setCredentials(credentials)
                        .setProjectId(projectId)
                        .build();
                FirebaseApp.initializeApp(options);
                firebaseAdminInitialized = true;
                logger.info("Firebase Admin SDK successfully initialized for project: {}", projectId);
            }
        } catch (Exception e) {
            logger.warn("Firebase Admin SDK initialization with service account failed: {}. Falling back to Google public certificate token verification.", e.getMessage());
        }
    }

    public FirebaseTokenClaims verifyFirebaseIdToken(String idToken) {
        if (idToken == null || idToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Firebase ID token must not be empty.");
        }

        // If Firebase Admin SDK is initialized, attempt verification via FirebaseAuth
        if (firebaseAdminInitialized) {
            try {
                FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken.trim());
                String uid = decodedToken.getUid();
                String email = decodedToken.getEmail();
                boolean emailVerified = decodedToken.isEmailVerified();

                return FirebaseTokenClaims.builder()
                        .uid(uid)
                        .email(email)
                        .emailVerified(emailVerified)
                        .build();
            } catch (Exception e) {
                logger.warn("FirebaseAuth verifyIdToken failed: {}. Attempting fallback public key verification.", e.getMessage());
            }
        }

        // Direct Cryptographic Verification via Google Public Keys (RFC 7515 / 7519)
        return verifyTokenWithGooglePublicKeys(idToken.trim());
    }

    /**
     * Cryptographically verifies Firebase ID Token according to Google's official specification:
     * 1. Header has "alg": "RS256" and a valid "kid".
     * 2. "kid" matches a valid certificate published by Google.
     * 3. Signature is cryptographically valid for the given public key.
     * 4. "aud" matches the Firebase project ID.
     * 5. "iss" matches "https://securetoken.google.com/<projectId>".
     * 6. "sub" is non-empty.
     * 7. "exp" is in the future.
     */
    public FirebaseTokenClaims verifyTokenWithGooglePublicKeys(String idToken) {
        try {
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Malformed Firebase ID token: must contain 3 parts.");
            }

            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

            JsonObject header = JsonParser.parseString(new String(headerBytes, StandardCharsets.UTF_8)).getAsJsonObject();
            JsonObject payload = JsonParser.parseString(new String(payloadBytes, StandardCharsets.UTF_8)).getAsJsonObject();

            // 1. Verify Algorithm
            String alg = header.has("alg") ? header.get("alg").getAsString() : "";
            if (!"RS256".equalsIgnoreCase(alg)) {
                throw new SecurityException("Invalid token algorithm: " + alg + ", expected RS256.");
            }

            // 2. Extract Key ID (kid)
            String kid = header.has("kid") ? header.get("kid").getAsString() : "";
            if (kid.isEmpty()) {
                throw new SecurityException("Missing 'kid' in Firebase token header.");
            }

            // 3. Retrieve Google Public Certificate
            X509Certificate cert = getGoogleCertificate(kid);
            if (cert == null) {
                throw new SecurityException("Public key certificate not found for kid: " + kid);
            }

            // 4. Verify Signature
            PublicKey publicKey = cert.getPublicKey();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            byte[] signedContent = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
            verifier.update(signedContent);
            if (!verifier.verify(signatureBytes)) {
                throw new SecurityException("Firebase ID token signature verification failed.");
            }

            // 5. Verify Audience
            String aud = payload.has("aud") ? payload.get("aud").getAsString() : "";
            if (!projectId.equals(aud)) {
                throw new SecurityException("Invalid token audience: " + aud + ", expected: " + projectId);
            }

            // 6. Verify Issuer
            String expectedIssuer = "https://securetoken.google.com/" + projectId;
            String iss = payload.has("iss") ? payload.get("iss").getAsString() : "";
            if (!expectedIssuer.equals(iss)) {
                throw new SecurityException("Invalid token issuer: " + iss + ", expected: " + expectedIssuer);
            }

            // 7. Verify Expiration
            long exp = payload.has("exp") ? payload.get("exp").getAsLong() : 0L;
            Instant now = Instant.now();
            Instant expInstant = Instant.ofEpochSecond(exp);
            // Allow 5 minutes clock skew
            if (now.isAfter(expInstant.plusSeconds(300))) {
                throw new SecurityException("Firebase ID token has expired at: " + expInstant);
            }

            // 8. Verify Subject (UID)
            String sub = payload.has("sub") ? payload.get("sub").getAsString() : "";
            if (sub.isEmpty()) {
                throw new SecurityException("Firebase ID token subject (sub) is empty.");
            }

            // 9. Extract Claims
            String email = payload.has("email") ? payload.get("email").getAsString() : null;
            boolean emailVerified = payload.has("email_verified") && payload.get("email_verified").getAsBoolean();

            return FirebaseTokenClaims.builder()
                    .uid(sub)
                    .email(email)
                    .emailVerified(emailVerified)
                    .build();

        } catch (SecurityException | IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Failed to cryptographically verify Firebase ID token: " + e.getMessage(), e);
        }
    }

    private synchronized X509Certificate getGoogleCertificate(String kid) {
        Instant now = Instant.now();
        if (certCache.containsKey(kid) && now.isBefore(certCacheExpiry)) {
            return certCache.get(kid);
        }

        refreshGoogleCertificates();
        return certCache.get(kid);
    }

    private void refreshGoogleCertificates() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GOOGLE_CERTS_URL))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                logger.error("Failed to fetch Google public certificates, status: {}", response.statusCode());
                return;
            }

            // Parse max-age from Cache-Control header if present
            long maxAgeSeconds = 3600; // default 1 hour
            String cacheControl = response.headers().firstValue("cache-control").orElse("");
            for (String directive : cacheControl.split(",")) {
                directive = directive.trim().toLowerCase();
                if (directive.startsWith("max-age=")) {
                    try {
                        maxAgeSeconds = Long.parseLong(directive.substring("max-age=".length()));
                    } catch (NumberFormatException ignored) {}
                }
            }

            JsonObject certsNode = JsonParser.parseString(response.body()).getAsJsonObject();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            certCache.clear();
            certsNode.entrySet().forEach(entry -> {
                try {
                    String certString = entry.getValue().getAsString();
                    ByteArrayInputStream certInputStream = new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8));
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certInputStream);
                    certCache.put(entry.getKey(), cert);
                } catch (Exception e) {
                    logger.warn("Could not parse certificate for kid: {}", entry.getKey(), e);
                }
            });

            certCacheExpiry = Instant.now().plusSeconds(maxAgeSeconds);
            logger.info("Refreshed Google public certificates. Cached {} keys for {} seconds.", certCache.size(), maxAgeSeconds);

        } catch (Exception e) {
            logger.error("Error refreshing Google public certificates: {}", e.getMessage(), e);
        }
    }

    public String getProjectId() {
        return projectId;
    }
}

