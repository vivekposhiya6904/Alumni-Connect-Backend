package com.alumni.management.exception;

import com.alumni.management.verification.exception.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<Map<String, Object>> handleNotFound(ResourceNotFoundException ex) {
		return buildResponse(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage());
	}

	@ExceptionHandler(InvalidOtpException.class)
	public ResponseEntity<Map<String, Object>> handleInvalidOtp(InvalidOtpException ex) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Invalid OTP", ex.getMessage());
	}

	@ExceptionHandler(OtpExpiredException.class)
	public ResponseEntity<Map<String, Object>> handleOtpExpired(OtpExpiredException ex) {
		return buildResponse(HttpStatus.BAD_REQUEST, "OTP Expired", ex.getMessage());
	}

	@ExceptionHandler(MaxAttemptsExceededException.class)
	public ResponseEntity<Map<String, Object>> handleMaxAttempts(MaxAttemptsExceededException ex) {
		return buildResponse(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", ex.getMessage());
	}

	@ExceptionHandler(ResendCooldownException.class)
	public ResponseEntity<Map<String, Object>> handleResendCooldown(ResendCooldownException ex) {
		Map<String, Object> error = new HashMap<>();
		error.put("timestamp", LocalDateTime.now());
		error.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
		error.put("error", "Rate Limit Exceeded");
		error.put("message", ex.getMessage());
		error.put("secondsRemaining", ex.getSecondsRemaining());
		return new ResponseEntity<>(error, HttpStatus.TOO_MANY_REQUESTS);
	}

	@ExceptionHandler(AccountNotVerifiedException.class)
	public ResponseEntity<Map<String, Object>> handleAccountNotVerified(AccountNotVerifiedException ex) {
		return buildResponse(HttpStatus.FORBIDDEN, "Forbidden", ex.getMessage());
	}

	@ExceptionHandler(UserAlreadyExistsException.class)
	public ResponseEntity<Map<String, Object>> handleUserAlreadyExists(UserAlreadyExistsException ex) {
		return buildResponse(HttpStatus.CONFLICT, "Conflict", ex.getMessage());
	}

	@ExceptionHandler(EmailDeliveryException.class)
	public ResponseEntity<Map<String, Object>> handleEmailDelivery(EmailDeliveryException ex) {
		return buildResponse(HttpStatus.SERVICE_UNAVAILABLE, "Service Unavailable", ex.getMessage());
	}

	@ExceptionHandler(SecurityException.class)
	public ResponseEntity<Map<String, Object>> handleSecurityException(SecurityException ex) {
		return buildResponse(HttpStatus.FORBIDDEN, "Forbidden", ex.getMessage());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
		String errorMessage = ex.getBindingResult().getFieldErrors().stream()
				.map(error -> error.getDefaultMessage())
				.findFirst()
				.orElse("Validation error");
		return buildResponse(HttpStatus.BAD_REQUEST, "Validation Error", errorMessage);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage());
	}

	@ExceptionHandler(IllegalStateException.class)
	public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException ex) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage());
	}

	private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String errorTitle, String message) {
		Map<String, Object> error = new HashMap<>();
		error.put("timestamp", LocalDateTime.now());
		error.put("status", status.value());
		error.put("error", errorTitle);
		error.put("message", message);
		return new ResponseEntity<>(error, status);
	}
}
