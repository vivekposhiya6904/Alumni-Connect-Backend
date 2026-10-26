package com.alumni.management.email.service;

import com.alumni.management.verification.enums.VerificationPurpose;
import com.alumni.management.verification.exception.EmailDeliveryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
    private static final String RESEND_API_URL = "https://api.resend.com/emails";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final Pattern ERROR_MESSAGE_PATTERN = Pattern.compile("\"message\"\\s*:\\s*\"([^\"]+)\"");

    private final String resendApiKey;
    private final String resendFromEmail;
    private final HttpClient httpClient;

    @Autowired
    public EmailService(
            @Value("${resend.api.key:${RESEND_API_KEY:}}") String resendApiKey,
            @Value("${resend.from.email:${RESEND_FROM_EMAIL:}}") String resendFromEmail
    ) {
        this(resendApiKey, resendFromEmail, HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .build());
    }

    public EmailService(
            String resendApiKey,
            String resendFromEmail,
            HttpClient httpClient
    ) {
        this.resendApiKey = resendApiKey != null ? resendApiKey.trim() : "";
        this.resendFromEmail = resendFromEmail != null ? resendFromEmail.trim() : "";
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    }

    /**
     * Send professional email verification OTP for account registration/activation.
     * Never logs sensitive OTP values to ensure production security.
     */
    public void sendVerificationOtpEmail(String toEmail, String otp, VerificationPurpose purpose) {
        String subject;
        if (purpose == VerificationPurpose.ACCOUNT_REGISTRATION) {
            subject = "GLS Connect - Account Registration Verification";
        } else if (purpose == VerificationPurpose.ACCOUNT_ACTIVATION) {
            subject = "GLS Connect - Account Activation Verification";
        } else {
            subject = "GLS Connect - Verification Code";
        }

        String text = "Dear User,\n\n"
                + "Thank you for using GLS Connect.\n\n"
                + "Your One-Time Password (OTP) for verification is:\n\n"
                + "  " + otp + "\n\n"
                + "This code is valid for 5 minutes. Please do not share this code with anyone.\n\n"
                + "If you did not request this verification, please ignore this email.\n\n"
                + "Best regards,\n"
                + "GLS Connect Team";

        sendEmailViaResend(toEmail, subject, text);
        logger.info("Verification email dispatched successfully for purpose: {}", purpose);
    }

    /**
     * Existing forgot-password OTP email sender preserved for backward compatibility.
     */
    public void sendOtpEmail(String toEmail, String otp) {
        String subject = "GLS Connect - Password Reset OTP";
        String text = "Dear User,\n\n"
                + "Your One-Time Password (OTP) for resetting your password on GLS Connect is:\n\n"
                + "  " + otp + "\n\n"
                + "This OTP is valid for 15 minutes. Please do not share this OTP with anyone.\n\n"
                + "Best regards,\n"
                + "GLS Connect Team";

        try {
            sendEmailViaResend(toEmail, subject, text);
            logger.info("Password reset OTP email sent successfully.");
        } catch (Exception e) {
            logger.error("Failed to send password reset OTP email: {}", e.getMessage());
        }
    }

    /**
     * Delivers an email message via Resend HTTPS API.
     */
    private void sendEmailViaResend(String toEmail, String subject, String text) {
        if (toEmail == null || toEmail.isBlank()) {
            logger.error("Recipient email address is missing or empty.");
            throw new EmailDeliveryException("Recipient email address is required.");
        }

        if (resendApiKey == null || resendApiKey.isBlank()) {
            logger.error("Resend API key is not configured. Please set the RESEND_API_KEY environment variable.");
            throw new EmailDeliveryException("Mail service is not configured with valid credentials. Please configure RESEND_API_KEY.");
        }

        if (resendFromEmail == null || resendFromEmail.isBlank()) {
            logger.error("Resend sender email is not configured. Please set the RESEND_FROM_EMAIL environment variable.");
            throw new EmailDeliveryException("Mail service sender address is not configured. Please configure RESEND_FROM_EMAIL.");
        }

        String sender = resolveSender(resendFromEmail);
        String requestBody = buildJsonPayload(sender, toEmail.trim(), subject, text);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(RESEND_API_URL))
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + resendApiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logger.error("Network error while connecting to Resend API: {}", e.getMessage());
            throw new EmailDeliveryException("Failed to send verification email due to network error. Please try again later.", e);
        }

        int statusCode = response.statusCode();
        if (statusCode >= 200 && statusCode < 300) {
            logger.info("Resend API accepted email delivery successfully (HTTP {}).", statusCode);
            return;
        }

        String safeErrorMessage = extractSafeErrorMessage(response.body(), statusCode);
        logger.error("Resend API rejected email delivery (HTTP {}): {}", statusCode, safeErrorMessage);
        throw new EmailDeliveryException("Failed to send verification email. " + safeErrorMessage);
    }

    private String resolveSender(String configuredFrom) {
        String trimmed = configuredFrom.trim();
        if (trimmed.contains("<") && trimmed.contains(">")) {
            return trimmed;
        }
        return "GLS Connect <" + trimmed + ">";
    }

    private String buildJsonPayload(String from, String to, String subject, String text) {
        return "{"
                + "\"from\":\"" + escapeJson(from) + "\","
                + "\"to\":[\"" + escapeJson(to) + "\"],"
                + "\"subject\":\"" + escapeJson(subject) + "\","
                + "\"text\":\"" + escapeJson(text) + "\""
                + "}";
    }

    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private String extractSafeErrorMessage(String responseBody, int statusCode) {
        if (responseBody != null && !responseBody.isBlank()) {
            try {
                Matcher matcher = ERROR_MESSAGE_PATTERN.matcher(responseBody);
                if (matcher.find()) {
                    String msg = matcher.group(1);
                    if (!msg.contains("Bearer") && (resendApiKey.isEmpty() || !msg.contains(resendApiKey))) {
                        return msg;
                    }
                }
            } catch (Exception ignored) {
                // Ignore extraction errors and fallback safely
            }
        }
        return "Please try again later. (HTTP " + statusCode + ")";
    }
}
