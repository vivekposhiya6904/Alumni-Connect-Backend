package com.alumni.management.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Loads root .env file as a low-precedence property source for local development.
 * In production (e.g. Render), real OS environment variables and system properties
 * automatically take precedence. If .env does not exist, it silently no-ops.
 */
@SuppressWarnings("deprecation")
public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    public static final String PROPERTY_SOURCE_NAME = "dotenvProperties";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        File envFile = findEnvFile();
        if (envFile == null || !envFile.exists() || !envFile.isFile() || envFile.length() == 0) {
            return;
        }

        Map<String, Object> dotenvMap = parseDotenv(envFile);
        if (!dotenvMap.isEmpty()) {
            environment.getPropertySources().addLast(new MapPropertySource(PROPERTY_SOURCE_NAME, dotenvMap));
        }
    }

    private File findEnvFile() {
        File current = new File(".env");
        if (current.exists() && current.isFile()) {
            return current;
        }
        File parent = new File("../.env");
        if (parent.exists() && parent.isFile()) {
            return parent;
        }
        return null;
    }

    private Map<String, Object> parseDotenv(File file) {
        Map<String, Object> map = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int eqIdx = line.indexOf('=');
                if (eqIdx > 0) {
                    String key = line.substring(0, eqIdx).trim();
                    String val = line.substring(eqIdx + 1).trim();
                    // Strip enclosing quotes if present (e.g. "value" or 'value')
                    if ((val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) ||
                        (val.startsWith("'") && val.endsWith("'") && val.length() >= 2)) {
                        val = val.substring(1, val.length() - 1);
                    }
                    map.put(key, val);
                }
            }
        } catch (IOException ignored) {
        }
        return map;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
