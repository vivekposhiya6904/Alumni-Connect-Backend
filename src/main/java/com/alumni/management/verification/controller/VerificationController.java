package com.alumni.management.verification.controller;

import com.alumni.management.verification.dto.FirebaseVerificationRequestDto;
import com.alumni.management.verification.dto.SendOtpRequestDto;
import com.alumni.management.verification.dto.VerificationResponseDto;
import com.alumni.management.verification.dto.VerifyOtpRequestDto;
import com.alumni.management.verification.service.VerificationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/verification")
public class VerificationController {

    private final VerificationService verificationService;

    public VerificationController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping("/firebase")
    public ResponseEntity<VerificationResponseDto> verifyFirebase(
            @Valid @RequestBody FirebaseVerificationRequestDto request
    ) {
        VerificationResponseDto response = verificationService.verifyFirebaseEmail(
                request.getEmail(),
                request.getIdToken()
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/send")
    public ResponseEntity<VerificationResponseDto> sendOtp(
            @Valid @RequestBody SendOtpRequestDto request
    ) {
        VerificationResponseDto response = verificationService.sendVerificationOtp(
                request.getEmail(),
                request.getPurpose()
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerificationResponseDto> verifyOtp(
            @Valid @RequestBody VerifyOtpRequestDto request
    ) {
        VerificationResponseDto response = verificationService.verifyOtp(
                request.getEmail(),
                request.getOtp(),
                request.getPurpose()
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend")
    public ResponseEntity<VerificationResponseDto> resendOtp(
            @Valid @RequestBody SendOtpRequestDto request
    ) {
        VerificationResponseDto response = verificationService.resendOtp(
                request.getEmail(),
                request.getPurpose()
        );
        return ResponseEntity.ok(response);
    }
}
