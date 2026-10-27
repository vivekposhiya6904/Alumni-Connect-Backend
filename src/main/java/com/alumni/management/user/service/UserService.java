package com.alumni.management.user.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.alumni.management.exception.ResourceNotFoundException;
import com.alumni.management.role.entity.Role;
import com.alumni.management.role.repository.RoleRepository;
import com.alumni.management.security.JwtUtil;
import com.alumni.management.user.dto.LoginRequestDto;
import com.alumni.management.user.dto.LoginResponseDto;
import com.alumni.management.user.dto.UserResponseDto;
import com.alumni.management.user.entity.User;
import com.alumni.management.user.repository.UserRepository;

@Service
public class UserService {

	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	PasswordEncoder passwordEncoder;
	@Autowired
	JwtUtil jwtUtil;
	@Autowired
	com.alumni.management.email.service.EmailService emailService;
	@Autowired
	com.alumni.management.verification.service.VerificationService verificationService;

	public User createUser(User user) {
		String normalizedEmail = user.getEmail() != null ? user.getEmail().trim().toLowerCase(java.util.Locale.ROOT) : "";
		user.setEmail(normalizedEmail);

		java.util.Optional<User> existingUserOpt = userRepository.findByEmail(normalizedEmail);
		if (existingUserOpt.isPresent()) {
			User existingUser = existingUserOpt.get();
			if (existingUser.isVerified()) {
				throw new com.alumni.management.verification.exception.UserAlreadyExistsException(
						"An account with this email is already registered and verified. Please log in.");
			}
			// Unverified account exists: update credentials and re-initiate verification
			existingUser.setName(user.getName());
			existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
			existingUser.setUniversityNumber(user.getUniversityNumber());

			String roleName = (user.getRole() != null && user.getRole().getRoleName() != null)
					? user.getRole().getRoleName()
					: "ALUMNI";
			Role role = roleRepository.findByRoleName(roleName)
					.orElseThrow(() -> new ResourceNotFoundException("Role not found"));
			existingUser.setRole(role);
			existingUser.setVerified(false);
			User saved = userRepository.save(existingUser);

			return saved;
		}

		String roleName = (user.getRole() != null && user.getRole().getRoleName() != null)
				? user.getRole().getRoleName()
				: "ALUMNI";
		Role role = roleRepository.findByRoleName(roleName)
				.orElseThrow(() -> new ResourceNotFoundException("Role not found"));

		user.setRole(role);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		user.setVerified(false);

		User saved = userRepository.save(user);

		return saved;
	}

//	We write list<userResponseDTO> because it give list of user dto(Dummy entity) not entity(DB)
	public List<UserResponseDto> getAllUsers() {
		List<User> users = userRepository.findAll();
		// stream() process users one by one

		return users.stream().map(user -> new UserResponseDto(
//				Convert each User → DTO (map)
				user.getId(), user.getName(), user.getEmail(), user.getRole().getRoleName()))
//				Collect results into a list
				.collect(Collectors.toList());
	}

//	We use dto class to secure password
	public UserResponseDto getUserById(Long id) {

		User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));

		return new UserResponseDto(user.getId(), user.getName(), user.getEmail(), user.getRole().getRoleName());
	}

	public void deleteUser(Long id) {
		User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
		if (user.getRole() != null && "ADMIN".equalsIgnoreCase(user.getRole().getRoleName())) {
			throw new IllegalArgumentException("Admin accounts cannot be deleted");
		}
		userRepository.delete(user);
	}

	public User updateUserData(Long id, User user) {
		String currentEmail = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication() != null
				? org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName()
				: null;
		if (currentEmail == null || "anonymousUser".equalsIgnoreCase(currentEmail)) {
			throw new SecurityException("Authentication required to update user data");
		}
		User currentUser = userRepository.findByEmail(currentEmail)
				.orElseThrow(() -> new ResourceNotFoundException("Authenticated user not found"));
		boolean isAdmin = currentUser.getRole() != null && "ADMIN".equalsIgnoreCase(currentUser.getRole().getRoleName());
		boolean isSelf = currentUser.getId().equals(id);

		if (!isAdmin && !isSelf) {
			throw new SecurityException("Unauthorized to update this user profile");
		}

		User existingUser = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found"));

		if (user.getName() != null && !user.getName().trim().isEmpty()) {
			existingUser.setName(user.getName().trim());
		}
		if (user.getEmail() != null && !user.getEmail().trim().isEmpty()) {
			existingUser.setEmail(user.getEmail().trim().toLowerCase(java.util.Locale.ROOT));
		}
		if (user.getPassword() != null && !user.getPassword().trim().isEmpty()) {
			existingUser.setPassword(passwordEncoder.encode(user.getPassword().trim()));
		}

		// check role exist if yes then ready to update - ONLY ADMIN can change roles
		if (user.getRole() != null && user.getRole().getRoleName() != null) {
			if (isAdmin) {
				Role role = roleRepository.findByRoleName(user.getRole().getRoleName())
						.orElseThrow(() -> new ResourceNotFoundException("Role not found"));
				existingUser.setRole(role);
			}
		}

		return userRepository.save(existingUser);
	}

	public LoginResponseDto login(LoginRequestDto request) {
		String normalizedEmail = request.getEmail() != null ? request.getEmail().trim().toLowerCase(java.util.Locale.ROOT) : "";

		User user = userRepository.findByEmail(normalizedEmail)
				.orElseThrow(() -> new ResourceNotFoundException("Invalid email or password"));

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new ResourceNotFoundException("Invalid email or password");
		}

		if (!user.isVerified()) {
			throw new com.alumni.management.verification.exception.AccountNotVerifiedException(
					"Account is not verified. Please verify your email before logging in.");
		}

	    String token = jwtUtil.generateToken(user.getEmail());

	    return new LoginResponseDto(
	    	    token,
	    	    user.getName(),
	    	    user.getRole().getRoleName()
	    	);
	}

	public UserResponseDto getCurrentUserProfile() {
		String email = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication() != null
				? org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName()
				: null;
		if (email == null || "anonymousUser".equalsIgnoreCase(email)) {
			throw new ResourceNotFoundException("No authenticated user found");
		}
		User user = userRepository.findByEmail(email.trim().toLowerCase(java.util.Locale.ROOT))
				.orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
		return new UserResponseDto(user.getId(), user.getName(), user.getEmail(), user.getRole() != null ? user.getRole().getRoleName() : "USER");
	}

	public java.util.Map<String, String> refreshToken() {
		String email = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication() != null
				? org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName()
				: null;
		if (email == null || "anonymousUser".equalsIgnoreCase(email)) {
			throw new SecurityException("Authentication required to refresh session");
		}
		User user = userRepository.findByEmail(email.trim().toLowerCase(java.util.Locale.ROOT))
				.orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
		String newToken = jwtUtil.generateToken(user.getEmail());
		java.util.Map<String, String> response = new java.util.HashMap<>();
		response.put("token", newToken);
		response.put("name", user.getName());
		response.put("role", user.getRole() != null ? user.getRole().getRoleName() : "USER");
		response.put("email", user.getEmail());
		return response;
	}
	
	
	public List<UserResponseDto> searchUsersByName(String name) {
	    List<User> users = userRepository.findByNameContainingIgnoreCase(name);
	    return users.stream()
	        .map(user -> new UserResponseDto(
	            user.getId(), 
	            user.getName(), 
	            user.getEmail(), 
	            user.getRole().getRoleName()))
	        .collect(Collectors.toList());
	}

	public java.util.Map<String, String> processForgotPassword(com.alumni.management.user.dto.ForgotPasswordRequestDto request) {
		String email = request.getEmail() != null ? request.getEmail().toLowerCase().trim() : "";
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new ResourceNotFoundException("User with email " + request.getEmail() + " not found"));

		verificationService.sendVerificationOtp(user.getEmail(), com.alumni.management.verification.enums.VerificationPurpose.PASSWORD_RESET);

		java.util.Map<String, String> response = new java.util.HashMap<>();
		response.put("message", "OTP sent successfully to your email");
		response.put("email", user.getEmail());
		return response;
	}

	public java.util.Map<String, String> resetPassword(com.alumni.management.user.dto.ResetPasswordRequestDto request) {
		String email = request.getEmail() != null ? request.getEmail().toLowerCase().trim() : "";
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new ResourceNotFoundException("User with email " + email + " not found"));

		verificationService.verifyOtp(email, request.getOtp() != null ? request.getOtp().trim() : "", com.alumni.management.verification.enums.VerificationPurpose.PASSWORD_RESET);

		user.setPassword(passwordEncoder.encode(request.getNewPassword()));
		userRepository.save(user);

		java.util.Map<String, String> response = new java.util.HashMap<>();
		response.put("message", "Password reset successfully");
		return response;
	}

}

