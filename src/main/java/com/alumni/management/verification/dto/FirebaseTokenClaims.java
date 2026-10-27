package com.alumni.management.verification.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FirebaseTokenClaims {
    private String uid;
    private String email;
    private boolean emailVerified;
}

