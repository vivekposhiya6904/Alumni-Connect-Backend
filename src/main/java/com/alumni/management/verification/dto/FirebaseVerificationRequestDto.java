package com.alumni.management.verification.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FirebaseVerificationRequestDto {

    @NotBlank(message = "Firebase ID token is required")
    private String idToken;

    @NotBlank(message = "Email is required")
    private String email;
}

