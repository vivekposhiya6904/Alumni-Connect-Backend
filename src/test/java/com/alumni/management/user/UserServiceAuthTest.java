package com.alumni.management.user;

import com.alumni.management.exception.ResourceNotFoundException;
import com.alumni.management.role.entity.Role;
import com.alumni.management.role.repository.RoleRepository;
import com.alumni.management.security.JwtUtil;
import com.alumni.management.user.dto.LoginRequestDto;
import com.alumni.management.user.dto.LoginResponseDto;
import com.alumni.management.user.entity.User;
import com.alumni.management.user.repository.UserRepository;
import com.alumni.management.user.service.UserService;
import com.alumni.management.verification.enums.VerificationPurpose;
import com.alumni.management.verification.exception.AccountNotVerifiedException;
import com.alumni.management.verification.exception.UserAlreadyExistsException;
import com.alumni.management.verification.service.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceAuthTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private VerificationService verificationService;

    @Spy
    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @InjectMocks
    private UserService userService;

    private final String testEmail = "alumni@gls.edu.in";
    private final String rawPassword = "SecurePassword123!";
    private Role alumniRole;

    @BeforeEach
    void setUp() {
        alumniRole = new Role();
        alumniRole.setId(1L);
        alumniRole.setRoleName("ALUMNI");
    }

    @Test
    @DisplayName("Unverified account must be rejected at login without issuing JWT")
    void testLogin_UnverifiedAccount_Rejected() {
        User unverifiedUser = new User();
        unverifiedUser.setEmail(testEmail);
        unverifiedUser.setPassword(passwordEncoder.encode(rawPassword));
        unverifiedUser.setRole(alumniRole);
        unverifiedUser.setVerified(false);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(unverifiedUser));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(testEmail);
        request.setPassword(rawPassword);

        AccountNotVerifiedException ex = assertThrows(AccountNotVerifiedException.class, () ->
                userService.login(request)
        );

        assertTrue(ex.getMessage().contains("Account is not verified"));
        verify(jwtUtil, never()).generateToken(anyString());
    }

    @Test
    @DisplayName("Verified account logs in successfully and receives JWT token without requiring OTP")
    void testLogin_VerifiedAccount_Succeeds() {
        User verifiedUser = new User();
        verifiedUser.setEmail(testEmail);
        verifiedUser.setName("John Doe");
        verifiedUser.setPassword(passwordEncoder.encode(rawPassword));
        verifiedUser.setRole(alumniRole);
        verifiedUser.setVerified(true);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(verifiedUser));
        when(jwtUtil.generateToken(testEmail)).thenReturn("mock.jwt.token");

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(testEmail);
        request.setPassword(rawPassword);

        LoginResponseDto response = userService.login(request);

        assertNotNull(response);
        assertEquals("mock.jwt.token", response.getToken());
        assertEquals("John Doe", response.getName());
        assertEquals("ALUMNI", response.getRole());

        // Verify normal login does NOT trigger OTP verification
        verify(verificationService, never()).sendVerificationOtp(anyString(), any());
    }

    @Test
    @DisplayName("Login with invalid password is rejected")
    void testLogin_InvalidPassword_Rejected() {
        User user = new User();
        user.setEmail(testEmail);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(alumniRole);
        user.setVerified(true);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail(testEmail);
        request.setPassword("WrongPassword!");

        assertThrows(ResourceNotFoundException.class, () -> userService.login(request));
        verify(jwtUtil, never()).generateToken(anyString());
    }

    @Test
    @DisplayName("Create user initiates verification with verified=false")
    void testCreateUser_NewUser_InitiatesVerification() {
        User newUser = new User();
        newUser.setEmail(testEmail);
        newUser.setName("New Student");
        newUser.setPassword(rawPassword);
        newUser.setRole(alumniRole);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.empty());
        when(roleRepository.findByRoleName("ALUMNI")).thenReturn(Optional.of(alumniRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = userService.createUser(newUser);

        assertNotNull(result);
        assertFalse(result.isVerified(), "New user must be unverified initially");
        assertTrue(passwordEncoder.matches(rawPassword, result.getPassword()), "Password must be BCrypt encoded");

        verify(verificationService, never()).sendVerificationOtp(anyString(), any());
    }

    @Test
    @DisplayName("Registration with already verified email is rejected")
    void testCreateUser_AlreadyVerified_Rejected() {
        User existingUser = new User();
        existingUser.setEmail(testEmail);
        existingUser.setVerified(true);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(existingUser));

        User registerAttempt = new User();
        registerAttempt.setEmail(testEmail);
        registerAttempt.setPassword(rawPassword);
        registerAttempt.setRole(alumniRole);

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(registerAttempt));
        verify(verificationService, never()).sendVerificationOtp(anyString(), any());
    }

    @Test
    @DisplayName("Duplicate registration with unverified email updates account and re-sends OTP")
    void testCreateUser_UnverifiedExisting_UpdatesAndResendsOtp() {
        User existingUnverified = new User();
        existingUnverified.setId(10L);
        existingUnverified.setEmail(testEmail);
        existingUnverified.setName("Old Name");
        existingUnverified.setPassword(passwordEncoder.encode("oldPassword"));
        existingUnverified.setRole(alumniRole);
        existingUnverified.setVerified(false);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(existingUnverified));
        when(roleRepository.findByRoleName("ALUMNI")).thenReturn(Optional.of(alumniRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User updatedAttempt = new User();
        updatedAttempt.setEmail(testEmail);
        updatedAttempt.setName("Updated Name");
        updatedAttempt.setPassword("NewSecretPassword!");
        updatedAttempt.setRole(alumniRole);

        User result = userService.createUser(updatedAttempt);

        assertEquals("Updated Name", result.getName());
        assertFalse(result.isVerified());
        assertTrue(passwordEncoder.matches("NewSecretPassword!", result.getPassword()));

        verify(verificationService, never()).sendVerificationOtp(anyString(), any());
    }

    @Test
    @DisplayName("deleteUser on ADMIN user is rejected with IllegalArgumentException")
    void deleteUser_AdminRole_ThrowsIllegalArgumentException() {
        Role adminRole = new Role("ADMIN");
        User adminUser = new User();
        adminUser.setId(99L);
        adminUser.setEmail("admin@alumni.com");
        adminUser.setRole(adminRole);

        when(userRepository.findById(99L)).thenReturn(Optional.of(adminUser));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            userService.deleteUser(99L);
        });

        assertEquals("Admin accounts cannot be deleted", ex.getMessage());
        verify(userRepository, never()).delete(adminUser);
        verify(userRepository, never()).deleteById(99L);
    }

    @Test
    @DisplayName("deleteUser on ordinary non-admin user succeeds")
    void deleteUser_OrdinaryUser_Succeeds() {
        Role studentRole = new Role("STUDENT");
        User studentUser = new User();
        studentUser.setId(105L);
        studentUser.setEmail("student@alumni.com");
        studentUser.setRole(studentRole);

        when(userRepository.findById(105L)).thenReturn(Optional.of(studentUser));

        assertDoesNotThrow(() -> userService.deleteUser(105L));
        verify(userRepository, times(1)).delete(studentUser);
    }

    @Test
    @DisplayName("Unverified STUDENT account must be rejected at login")
    void testLogin_UnverifiedStudent_Rejected() {
        Role studentRole = new Role("STUDENT");
        User unverifiedStudent = new User();
        unverifiedStudent.setEmail("student@gls.edu.in");
        unverifiedStudent.setPassword(passwordEncoder.encode(rawPassword));
        unverifiedStudent.setRole(studentRole);
        unverifiedStudent.setVerified(false);

        when(userRepository.findByEmail("student@gls.edu.in")).thenReturn(Optional.of(unverifiedStudent));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail("student@gls.edu.in");
        request.setPassword(rawPassword);

        AccountNotVerifiedException ex = assertThrows(AccountNotVerifiedException.class, () ->
                userService.login(request)
        );

        assertTrue(ex.getMessage().contains("Account is not verified"));
        verify(jwtUtil, never()).generateToken(anyString());
    }

    @Test
    @DisplayName("Unverified FACULTY account must be rejected at login")
    void testLogin_UnverifiedFaculty_Rejected() {
        Role facultyRole = new Role("FACULTY");
        User unverifiedFaculty = new User();
        unverifiedFaculty.setEmail("faculty@gls.edu.in");
        unverifiedFaculty.setPassword(passwordEncoder.encode(rawPassword));
        unverifiedFaculty.setRole(facultyRole);
        unverifiedFaculty.setVerified(false);

        when(userRepository.findByEmail("faculty@gls.edu.in")).thenReturn(Optional.of(unverifiedFaculty));

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail("faculty@gls.edu.in");
        request.setPassword(rawPassword);

        AccountNotVerifiedException ex = assertThrows(AccountNotVerifiedException.class, () ->
                userService.login(request)
        );

        assertTrue(ex.getMessage().contains("Account is not verified"));
        verify(jwtUtil, never()).generateToken(anyString());
    }

    @Test
    @DisplayName("Verified STUDENT account logs in successfully and receives JWT")
    void testLogin_VerifiedStudent_Succeeds() {
        Role studentRole = new Role("STUDENT");
        User verifiedStudent = new User();
        verifiedStudent.setEmail("student@gls.edu.in");
        verifiedStudent.setName("Kathan Student");
        verifiedStudent.setPassword(passwordEncoder.encode(rawPassword));
        verifiedStudent.setRole(studentRole);
        verifiedStudent.setVerified(true);

        when(userRepository.findByEmail("student@gls.edu.in")).thenReturn(Optional.of(verifiedStudent));
        when(jwtUtil.generateToken("student@gls.edu.in")).thenReturn("mock.student.jwt");

        LoginRequestDto request = new LoginRequestDto();
        request.setEmail("student@gls.edu.in");
        request.setPassword(rawPassword);

        LoginResponseDto response = userService.login(request);

        assertNotNull(response);
        assertEquals("mock.student.jwt", response.getToken());
        assertEquals("Kathan Student", response.getName());
        assertEquals("STUDENT", response.getRole());
    }

    @Test
    @DisplayName("getCurrentUserProfile returns user profile attributes safely")
    void testGetCurrentUserProfile_Success() {
        User user = new User();
        user.setId(10L);
        user.setEmail(testEmail);
        user.setName("Alice Alumni");
        user.setRole(alumniRole);
        user.setUniversityNumber("GLS1234");
        user.setVerified(true);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));

        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(testEmail, null)
        );

        com.alumni.management.user.dto.UserResponseDto profile = userService.getCurrentUserProfile();

        assertNotNull(profile);
        assertEquals(10L, profile.getId());
        assertEquals("Alice Alumni", profile.getName());
        assertEquals(testEmail, profile.getEmail());
        assertEquals("ALUMNI", profile.getRoleName());
    }

    @Test
    @DisplayName("refreshToken returns new token and user details")
    void testRefreshToken_Success() {
        User user = new User();
        user.setEmail(testEmail);
        user.setName("Alice Alumni");
        user.setRole(alumniRole);

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken(testEmail)).thenReturn("refreshed.new.token");

        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(testEmail, null)
        );

        java.util.Map<String, String> result = userService.refreshToken();

        assertNotNull(result);
        assertEquals("refreshed.new.token", result.get("token"));
        assertEquals("Alice Alumni", result.get("name"));
        assertEquals("ALUMNI", result.get("role"));
    }

    @Test
    @DisplayName("processForgotPassword dispatches OTP via VerificationService")
    void testProcessForgotPassword_Success() {
        User user = new User();
        user.setEmail(testEmail);
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));

        com.alumni.management.user.dto.ForgotPasswordRequestDto req = new com.alumni.management.user.dto.ForgotPasswordRequestDto();
        req.setEmail(testEmail);

        java.util.Map<String, String> response = userService.processForgotPassword(req);
        assertNotNull(response);
        assertEquals(testEmail, response.get("email"));
        verify(verificationService).sendVerificationOtp(testEmail, VerificationPurpose.PASSWORD_RESET);
    }

    @Test
    @DisplayName("resetPassword verifies OTP via VerificationService and hashes new password")
    void testResetPassword_Success() {
        User user = new User();
        user.setEmail(testEmail);
        user.setPassword(passwordEncoder.encode("OldPassword123!"));
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));

        com.alumni.management.user.dto.ResetPasswordRequestDto req = new com.alumni.management.user.dto.ResetPasswordRequestDto();
        req.setEmail(testEmail);
        req.setOtp("123456");
        req.setNewPassword("NewSecurePassword456!");

        java.util.Map<String, String> response = userService.resetPassword(req);
        assertNotNull(response);
        assertEquals("Password reset successfully", response.get("message"));

        verify(verificationService).verifyOtp(testEmail, "123456", VerificationPurpose.PASSWORD_RESET);
        verify(userRepository).save(argThat(savedUser ->
            passwordEncoder.matches("NewSecurePassword456!", savedUser.getPassword())
        ));
    }
}


