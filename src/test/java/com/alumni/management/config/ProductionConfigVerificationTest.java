package com.alumni.management.config;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import com.alumni.management.security.JwtUtil;

public class ProductionConfigVerificationTest {

    @Test
    @DisplayName("Verify application-prod.properties exists on classpath and references required env vars without secrets")
    void testProductionPropertiesExistAndHaveNoHardcodedSecrets() throws Exception {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("application-prod.properties")) {
            assertNotNull(is, "application-prod.properties must exist on classpath for prod profile");
            Properties props = new Properties();
            props.load(is);

            // Check PostgreSQL properties
            assertEquals("${SPRING_DATASOURCE_URL}", props.getProperty("spring.datasource.url"));
            assertEquals("${SPRING_DATASOURCE_USERNAME}", props.getProperty("spring.datasource.username"));
            assertEquals("${SPRING_DATASOURCE_PASSWORD}", props.getProperty("spring.datasource.password"));
            assertEquals("update", props.getProperty("spring.jpa.hibernate.ddl-auto"));

            // Check MongoDB properties
            assertEquals("${SPRING_DATA_MONGODB_URI}", props.getProperty("spring.data.mongodb.uri"));
            assertEquals("true", props.getProperty("spring.data.mongodb.auto-index-creation"));

            // Check JWT properties
            assertEquals("${JWT_SECRET}", props.getProperty("jwt.secret"));

            // Verify no passwords or keys are hardcoded in prod properties
            for (String key : props.stringPropertyNames()) {
                String val = props.getProperty(key);
                assertFalse(val.contains("7DLNVEI"), "Must not contain compromised database credentials");
                assertFalse(val.contains("password123"), "Must not contain plaintext fallback password");
            }
        }
    }

    @Test
    @DisplayName("Verify JwtUtil enforces 256-bit requirement and blocks default secret in prod profile")
    void testJwtUtilEnforcesProductionSecurity() {
        JwtUtil jwtUtil = new JwtUtil();
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        ReflectionTestUtils.setField(jwtUtil, "environment", env);
        ReflectionTestUtils.setField(jwtUtil, "secret", "ThisIsASecretKeyForJwtGeneration123456"); // Default secret

        IllegalStateException ex = assertThrows(IllegalStateException.class, jwtUtil::init);
        assertTrue(ex.getMessage().contains("CRITICAL SECURITY CONFIGURATION ERROR"));

        // Now test with valid 256-bit secret
        ReflectionTestUtils.setField(jwtUtil, "secret", "A_Very_Strong_And_Secure_Random_Token_Key_For_Production_256_Bits!");
        ReflectionTestUtils.setField(jwtUtil, "expirationMs", 2592000000L);
        assertDoesNotThrow(jwtUtil::init);
    }
}
