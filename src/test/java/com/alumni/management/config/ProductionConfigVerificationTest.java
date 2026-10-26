package com.alumni.management.config;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.StandardEnvironment;
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

            // Check CORS is not wildarded blindly
            assertNotEquals("*", props.getProperty("cors.allowed.origins"));

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

    @Test
    @DisplayName("Verify DotenvEnvironmentPostProcessor safely parses .env and strips quotes")
    void testDotenvEnvironmentPostProcessorParsesCorrectly() throws Exception {
        DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor();
        StandardEnvironment env = new StandardEnvironment();
        SpringApplication app = new SpringApplication();

        // Create a temporary .env file
        File tempEnv = File.createTempFile("test", ".env");
        tempEnv.deleteOnExit();
        List<String> lines = List.of(
            "# Comment line",
            "TEST_VAR_PLAIN=hello_world",
            "TEST_VAR_QUOTED=\"quoted_value\"",
            "TEST_VAR_SINGLE_QUOTED='single_quoted'",
            "TEST_VAR_JDBC=jdbc:postgresql://localhost:5432/testdb"
        );
        Files.write(tempEnv.toPath(), lines);

        // Invoke parseDotenv via reflection
        java.lang.reflect.Method parseMethod = DotenvEnvironmentPostProcessor.class.getDeclaredMethod("parseDotenv", File.class);
        parseMethod.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> result = (java.util.Map<String, Object>) parseMethod.invoke(processor, tempEnv);

        assertEquals("hello_world", result.get("TEST_VAR_PLAIN"));
        assertEquals("quoted_value", result.get("TEST_VAR_QUOTED"));
        assertEquals("single_quoted", result.get("TEST_VAR_SINGLE_QUOTED"));
        assertEquals("jdbc:postgresql://localhost:5432/testdb", result.get("TEST_VAR_JDBC"));
        assertNull(result.get("# Comment line"));
    }

    @Test
    @DisplayName("Verify .env.example contains all required keys without real secrets")
    void testEnvExampleContainsRequiredKeys() throws Exception {
        File exampleFile = new File(".env.example");
        assertTrue(exampleFile.exists(), ".env.example must exist in project root");
        String content = Files.readString(exampleFile.toPath());

        assertTrue(content.contains("SPRING_DATASOURCE_URL="));
        assertTrue(content.contains("SPRING_DATASOURCE_USERNAME="));
        assertTrue(content.contains("SPRING_DATASOURCE_PASSWORD="));
        assertTrue(content.contains("SPRING_DATA_MONGODB_URI="));
        assertTrue(content.contains("JWT_SECRET="));
        assertTrue(content.contains("SPRING_MAIL_USERNAME="));
        assertTrue(content.contains("SPRING_MAIL_PASSWORD="));
        assertTrue(content.contains("CORS_ALLOWED_ORIGINS="));
        assertTrue(content.contains("APP_UPLOAD_DIR="));

        // Ensure no real database or SMTP passwords in .env.example
        assertFalse(content.contains("7DLNVEI"), ".env.example must not contain compromised database credentials");
        assertFalse(content.contains("aezt xnxe"), ".env.example must not contain real SMTP password");
    }
}
