package com.alumni.management.security.SecurityConfig;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.alumni.management.security.JwtFilter.JwtFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                    // Public endpoints
                    .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                    .requestMatchers("/error").permitAll()
                    .requestMatchers("/api/health", "/api/health/**").permitAll()
                    .requestMatchers("/chat/**").permitAll()
                    .requestMatchers("/api/chat/**").authenticated()
                    .requestMatchers("/api/users/login").permitAll()
                    .requestMatchers("/api/users/forgot-password").permitAll()
                    .requestMatchers("/api/users/reset-password").permitAll()
                    .requestMatchers("/api/users").permitAll()
                    .requestMatchers("/api/auth/verification/**").permitAll()
                    .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/events").permitAll()
                    .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/jobs").permitAll()
                    .requestMatchers("/uploads/**").permitAll()

                    // Admin endpoints
                    .requestMatchers("/api/events/admin/**").hasRole("ADMIN")
                    .requestMatchers("/api/admin/**").hasRole("ADMIN")

                    // Authenticated endpoints
                    .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/events").authenticated()
                    .requestMatchers("/api/events/my").authenticated()

                    // Everything else
                    .anyRequest().authenticated()
            )
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(jwtFilter,
                    org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @org.springframework.beans.factory.annotation.Value("${cors.allowed.origins:http://localhost:*,http://127.0.0.1:*,http://10.0.2.2:*,http://192.168.*}")
    private String allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> origins = java.util.Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toList());
        configuration.setAllowedOriginPatterns(origins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}