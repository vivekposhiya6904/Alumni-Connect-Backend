package com.alumni.management.verification;

import com.alumni.management.email.service.EmailService;
import com.alumni.management.exception.ResourceNotFoundException;
import com.alumni.management.role.entity.Role;
import com.alumni.management.role.repository.RoleRepository;
import com.alumni.management.security.JwtUtil;
import com.alumni.management.user.dto.LoginRequestDto;
import com.alumni.management.user.dto.LoginResponseDto;
import com.alumni.management.user.entity.User;
import com.alumni.management.user.repository.UserRepository;
import com.alumni.management.user.service.UserService;
import com.alumni.management.verification.controller.VerificationController;
import com.alumni.management.verification.dto.FirebaseTokenClaims;
import com.alumni.management.verification.dto.FirebaseVerificationRequestDto;
import com.alumni.management.verification.dto.VerificationResponseDto;
import com.alumni.management.verification.exception.AccountNotVerifiedException;
import com.alumni.management.verification.repository.EmailVerificationRepository;
import com.alumni.management.verification.service.FirebaseTokenService;
import com.alumni.management.verification.service.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FirebaseVerificationTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailVerificationRepository verificationRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private FirebaseTokenService firebaseTokenService;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private JwtUtil jwtUtil;

    private PasswordEncoder passwordEncoder;
    private VerificationService verificationService;
    private VerificationController verificationController;
    private UserService userService;

    private final String studentEmail = "student.gls@example.com";
    private final String facultyEmail = "faculty.gls@example.com";
    private final String sampleUid = "firebase_uid_abc123";

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        verificationService = new VerificationService(
                verificationRepository,
                userRepository,
                emailService,
                passwordEncoder,
                firebaseTokenService
        );
        verificationController = new VerificationController(verificationService);

        userService = new UserService();
        // inject fields manually for UserService tests
        try {
            var fUserRepo = UserService.class.getDeclaredField("userRepository");
            fUserRepo.setAccessible(true);
            fUserRepo.set(userService, userRepository);

            var fRoleRepo = UserService.class.getDeclaredField("roleRepository");
            fRoleRepo.setAccessible(true);
            fRoleRepo.set(userService, roleRepository);

            var fEncoder = UserService.class.getDeclaredField("passwordEncoder");
            fEncoder.setAccessible(true);
            fEncoder.set(userService, passwordEncoder);

            var fJwt = UserService.class.getDeclaredField("jwtUtil");
            fJwt.setAccessible(true);
            fJwt.set(userService, jwtUtil);

            var fVerif = UserService.class.getDeclaredField("verificationService");
            fVerif.setAccessible(true);
            fVerif.set(userService, verificationService);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("1. Verified Firebase token activates student account and associates Firebase UID")
    void testVerifyFirebaseEmail_StudentSuccess() {
        User student = new User();
        student.setId(101L);
        student.setName("Student Test");
        student.setEmail(studentEmail);
        student.setVerified(false);

        when(firebaseTokenService.verifyFirebaseIdToken("valid_token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email(studentEmail)
                        .emailVerified(true)
                        .build());
        when(userRepository.findByEmail(studentEmail)).thenReturn(Optional.of(student));
        when(userRepository.findByFirebaseUid(sampleUid)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        VerificationResponseDto response = verificationService.verifyFirebaseEmail(studentEmail, "valid_token");

        assertTrue(response.isSuccess());
        assertTrue(student.isVerified());
        assertEquals(sampleUid, student.getFirebaseUid());
        verify(userRepository, times(1)).save(student);
    }

    @Test
    @DisplayName("2. Verified Firebase token activates faculty account and associates Firebase UID")
    void testVerifyFirebaseEmail_FacultySuccess() {
        User faculty = new User();
        faculty.setId(202L);
        faculty.setName("Prof. Faculty");
        faculty.setEmail(facultyEmail);
        faculty.setVerified(false);

        when(firebaseTokenService.verifyFirebaseIdToken("valid_token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid("firebase_uid_faculty")
                        .email(facultyEmail)
                        .emailVerified(true)
                        .build());
        when(userRepository.findByEmail(facultyEmail)).thenReturn(Optional.of(faculty));
        when(userRepository.findByFirebaseUid("firebase_uid_faculty")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        VerificationResponseDto response = verificationService.verifyFirebaseEmail(facultyEmail, "valid_token");

        assertTrue(response.isSuccess());
        assertTrue(faculty.isVerified());
        assertEquals("firebase_uid_faculty", faculty.getFirebaseUid());
    }

    @Test
    @DisplayName("3. Unverified Firebase email (link not clicked) is rejected with SecurityException")
    void testVerifyFirebaseEmail_UnverifiedTokenRejected() {
        when(firebaseTokenService.verifyFirebaseIdToken("unverified_token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email(studentEmail)
                        .emailVerified(false)
                        .build());

        SecurityException ex = assertThrows(SecurityException.class, () ->
                verificationService.verifyFirebaseEmail(studentEmail, "unverified_token")
        );
        assertTrue(ex.getMessage().contains("Email has not been verified yet in Firebase"));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("4. Mismatched registered email is rejected safely")
    void testVerifyFirebaseEmail_MismatchedEmailRejected() {
        when(firebaseTokenService.verifyFirebaseIdToken("mismatch_token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email("attacker@example.com")
                        .emailVerified(true)
                        .build());

        SecurityException ex = assertThrows(SecurityException.class, () ->
                verificationService.verifyFirebaseEmail(studentEmail, "mismatch_token")
        );
        assertTrue(ex.getMessage().contains("does not match registered application email"));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("5. Non-existent user email is rejected with ResourceNotFoundException")
    void testVerifyFirebaseEmail_UserNotFound() {
        when(firebaseTokenService.verifyFirebaseIdToken("token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email("unknown@example.com")
                        .emailVerified(true)
                        .build());
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                verificationService.verifyFirebaseEmail("unknown@example.com", "token")
        );
    }

    @Test
    @DisplayName("6. Prevent duplicate UID association across different users")
    void testVerifyFirebaseEmail_PreventDuplicateUidStealing() {
        User user1 = new User();
        user1.setId(1L);
        user1.setEmail(studentEmail);

        User user2 = new User();
        user2.setId(2L);
        user2.setEmail("other@example.com");
        user2.setFirebaseUid(sampleUid);

        when(firebaseTokenService.verifyFirebaseIdToken("token"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email(studentEmail)
                        .emailVerified(true)
                        .build());
        when(userRepository.findByEmail(studentEmail)).thenReturn(Optional.of(user1));
        when(userRepository.findByFirebaseUid(sampleUid)).thenReturn(Optional.of(user2));

        SecurityException ex = assertThrows(SecurityException.class, () ->
                verificationService.verifyFirebaseEmail(studentEmail, "token")
        );
        assertTrue(ex.getMessage().contains("already associated with another account"));
    }

    @Test
    @DisplayName("7. Unverified student cannot complete application login")
    void testUnverifiedStudent_CannotLogin() {
        User student = new User();
        student.setId(101L);
        student.setEmail(studentEmail);
        student.setPassword(passwordEncoder.encode("SecretPass123"));
        student.setVerified(false);

        Role role = new Role();
        role.setRoleName("STUDENT");
        student.setRole(role);

        when(userRepository.findByEmail(studentEmail)).thenReturn(Optional.of(student));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(studentEmail);
        request.setPassword("SecretPass123");

        assertThrows(AccountNotVerifiedException.class, () -> userService.login(request));
    }

    @Test
    @DisplayName("8. Unverified faculty member cannot complete application login")
    void testUnverifiedFaculty_CannotLogin() {
        User faculty = new User();
        faculty.setId(202L);
        faculty.setEmail(facultyEmail);
        faculty.setPassword(passwordEncoder.encode("FacultyPass456"));
        faculty.setVerified(false);

        Role role = new Role();
        role.setRoleName("FACULTY");
        faculty.setRole(role);

        when(userRepository.findByEmail(facultyEmail)).thenReturn(Optional.of(faculty));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(facultyEmail);
        request.setPassword("FacultyPass456");

        assertThrows(AccountNotVerifiedException.class, () -> userService.login(request));
    }

    @Test
    @DisplayName("9. Verified student can log in and receives JWT token")
    void testVerifiedStudent_CanLogin() {
        User student = new User();
        student.setId(101L);
        student.setName("Student Verified");
        student.setEmail(studentEmail);
        student.setPassword(passwordEncoder.encode("SecretPass123"));
        student.setVerified(true);

        Role role = new Role();
        role.setRoleName("STUDENT");
        student.setRole(role);

        when(userRepository.findByEmail(studentEmail)).thenReturn(Optional.of(student));
        when(jwtUtil.generateToken(studentEmail)).thenReturn("mock_jwt_token_student");

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(studentEmail);
        request.setPassword("SecretPass123");

        LoginResponseDto response = userService.login(request);
        assertNotNull(response);
        assertEquals("mock_jwt_token_student", response.getToken());
        assertEquals("STUDENT", response.getRole());
    }

    @Test
    @DisplayName("10. Controller endpoint POST /api/auth/verification/firebase delegates and returns 200 OK")
    void testControllerEndpoint_Success() {
        User user = new User();
        user.setId(505L);
        user.setEmail(studentEmail);
        user.setVerified(false);

        when(firebaseTokenService.verifyFirebaseIdToken("token123"))
                .thenReturn(FirebaseTokenClaims.builder()
                        .uid(sampleUid)
                        .email(studentEmail)
                        .emailVerified(true)
                        .build());
        when(userRepository.findByEmail(studentEmail)).thenReturn(Optional.of(user));
        when(userRepository.findByFirebaseUid(sampleUid)).thenReturn(Optional.empty());

        FirebaseVerificationRequestDto requestDto = FirebaseVerificationRequestDto.builder()
                .email(studentEmail)
                .idToken("token123")
                .build();

        ResponseEntity<VerificationResponseDto> responseEntity = verificationController.verifyFirebase(requestDto);
        assertEquals(200, responseEntity.getStatusCode().value());
        assertTrue(responseEntity.getBody().isSuccess());
        assertEquals("Email verified successfully via Firebase.", responseEntity.getBody().getMessage());
    }
}

