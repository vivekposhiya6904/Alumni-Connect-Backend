package com.alumni.management.admin.service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.alumni.management.admin.dto.AdminStatsDto;
import com.alumni.management.admin.dto.CreateUserRequestDto;
import com.alumni.management.alumni.entity.AlumniProfile;
import com.alumni.management.alumni.repository.AlumniProfileRepository;
import com.alumni.management.event.entity.Event;
import com.alumni.management.event.repository.EventRepository;
import com.alumni.management.exception.ResourceNotFoundException;
import com.alumni.management.faculty.entity.FacultyProfile;
import com.alumni.management.faculty.repository.FacultyRepository;
import com.alumni.management.jobpost.entity.Job;
import com.alumni.management.jobpost.repository.JobRepository;
import com.alumni.management.post.entity.Post;
import com.alumni.management.post.repository.PostRepository;
import com.alumni.management.role.entity.Role;
import com.alumni.management.role.repository.RoleRepository;
import com.alumni.management.user.dto.UserResponseDto;
import com.alumni.management.user.entity.User;
import com.alumni.management.user.repository.UserRepository;

@Service
public class AdminService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired(required = false)
	private AlumniProfileRepository alumniProfileRepository;

	@Autowired(required = false)
	private FacultyRepository facultyRepository;

	@Autowired(required = false)
	private com.alumni.management.student.repository.StudentProfileRepository studentProfileRepository;

	@Autowired(required = false)
	private JobRepository jobRepository;

	@Autowired(required = false)
	private EventRepository eventRepository;

	@Autowired(required = false)
	private PostRepository postRepository;

	@Autowired(required = false)
	private com.alumni.management.verification.service.VerificationService verificationService;

	private String getUserDepartment(User user) {
		String role = user.getRole() != null ? user.getRole().getRoleName().toUpperCase() : "";
		if ("ALUMNI".equals(role) && alumniProfileRepository != null) {
			Optional<AlumniProfile> ap = alumniProfileRepository.findByUserId(user.getId());
			if (ap.isPresent() && ap.get().getDepartment() != null && !ap.get().getDepartment().isEmpty()) {
				return ap.get().getDepartment();
			}
		} else if ("FACULTY".equals(role) && facultyRepository != null) {
			Optional<FacultyProfile> fp = facultyRepository.findByUserId(user.getId());
			if (fp.isPresent() && fp.get().getDepartment() != null && !fp.get().getDepartment().isEmpty()) {
				return fp.get().getDepartment();
			}
		} else if ("STUDENT".equals(role) && studentProfileRepository != null) {
			Optional<com.alumni.management.student.entity.StudentProfile> sp = studentProfileRepository.findByUserId(user.getId());
			if (sp.isPresent() && sp.get().getDepartment() != null && !sp.get().getDepartment().isEmpty()) {
				return sp.get().getDepartment();
			}
		}
		return "MCA"; // Default department
	}

	public List<UserResponseDto> getAllUsers() {
		List<User> users = userRepository.findAll();
		return users.stream()
				.filter(user -> user.getRole() == null || !"ADMIN".equalsIgnoreCase(user.getRole().getRoleName()))
				.map(user -> new UserResponseDto(
						user.getId(),
						user.getName(),
						user.getEmail(),
						user.getRole() != null ? user.getRole().getRoleName() : "USER",
						getUserDepartment(user)
				)).collect(Collectors.toList());
	}

	public List<UserResponseDto> getUserByRole(String roleName) {
		if ("ADMIN".equalsIgnoreCase(roleName)) {
			return List.of();
		}
		List<User> users = userRepository.findByRole_RoleName(roleName);
		if (users.isEmpty()) {
			return List.of();
		}
		return users.stream()
				.filter(user -> user.getRole() == null || !"ADMIN".equalsIgnoreCase(user.getRole().getRoleName()))
				.map(user -> new UserResponseDto(
						user.getId(),
						user.getName(),
						user.getEmail(),
						user.getRole() != null ? user.getRole().getRoleName() : "USER",
						getUserDepartment(user)
				)).collect(Collectors.toList());
	}

	public AdminStatsDto getAdminStats() {
		List<User> allUsers = userRepository.findAll();
		long totalUsers = allUsers.stream().filter(u -> u.getRole() == null || !"ADMIN".equalsIgnoreCase(u.getRole().getRoleName())).count();
		long totalAlumni = allUsers.stream().filter(u -> u.getRole() != null && "ALUMNI".equalsIgnoreCase(u.getRole().getRoleName())).count();
		long totalFaculty = allUsers.stream().filter(u -> u.getRole() != null && "FACULTY".equalsIgnoreCase(u.getRole().getRoleName())).count();
		long totalStudents = allUsers.stream().filter(u -> u.getRole() != null && "STUDENT".equalsIgnoreCase(u.getRole().getRoleName())).count();

		long totalJobs = 0;
		long activeJobs = 0;
		if (jobRepository != null) {
			List<Job> jobs = jobRepository.findAll();
			totalJobs = jobs.size();
			LocalDate today = LocalDate.now();
			activeJobs = jobs.stream().filter(job -> {
				if (job.getLastDateToApply() == null) {
					return true;
				}
				return !job.getLastDateToApply().isBefore(today);
			}).count();
		}

		long totalEvents = 0;
		long activeEvents = 0;
		if (eventRepository != null) {
			List<Event> events = eventRepository.findAll();
			totalEvents = events.size();
			LocalDate today = LocalDate.now();
			activeEvents = events.stream().filter(evt -> {
				if (evt.getEventDate() == null) return true;
				return !evt.getEventDate().isBefore(today);
			}).count();
		}

		return new AdminStatsDto(
				totalUsers,
				totalAlumni,
				totalFaculty,
				totalStudents,
				totalJobs,
				activeJobs,
				totalEvents,
				activeEvents
		);
	}

	@Transactional
	public String deleteUser(Long userId) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id " + userId));

		if (user.getRole() != null && "ADMIN".equalsIgnoreCase(user.getRole().getRoleName())) {
			throw new IllegalArgumentException("Admin accounts cannot be deleted");
		}

		// Clean up profile associated strictly with this specific user
		if (alumniProfileRepository != null) {
			Optional<AlumniProfile> ap = alumniProfileRepository.findByUserId(userId);
			ap.ifPresent(alumniProfileRepository::delete);
		}
		if (facultyRepository != null) {
			Optional<FacultyProfile> fp = facultyRepository.findByUserId(userId);
			fp.ifPresent(facultyRepository::delete);
		}
		if (studentProfileRepository != null) {
			Optional<com.alumni.management.student.entity.StudentProfile> sp = studentProfileRepository.findByUserId(userId);
			sp.ifPresent(studentProfileRepository::delete);
		}

		// Clean up posts created strictly by this user
		if (postRepository != null) {
			List<Post> userPosts = postRepository.findByUserIdOrderByCreatedAtDesc(userId);
			if (userPosts != null && !userPosts.isEmpty()) {
				postRepository.deleteAll(userPosts);
			}
		}

		// Clean up jobs created strictly by this user
		if (jobRepository != null) {
			List<Job> userJobs = jobRepository.findByUserId(userId);
			if (userJobs != null && !userJobs.isEmpty()) {
				jobRepository.deleteAll(userJobs);
			}
		}

		// Clean up events created strictly by this user
		if (eventRepository != null) {
			List<Event> userEvents = eventRepository.findByCreatedBy_Id(userId);
			if (userEvents != null && !userEvents.isEmpty()) {
				eventRepository.deleteAll(userEvents);
			}
		}

		userRepository.delete(user);
		return "User deleted successfully";
	}

	public UserResponseDto createUserByAdmin(CreateUserRequestDto request) {
		String roleStr = request.getRoleName() != null ? request.getRoleName().toUpperCase() : "USER";
		Role role = roleRepository.findByRoleName(roleStr)
				.orElseThrow(() -> new ResourceNotFoundException("Role " + roleStr + " not found"));

		User user = new User();
		user.setName(request.getName());
		user.setEmail(request.getEmail() != null ? request.getEmail().trim().toLowerCase(java.util.Locale.ROOT) : "");
		user.setVerified(false);
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(role);

		User savedUser = userRepository.save(user);


		String dept = request.getDepartment() != null && !request.getDepartment().isEmpty() ? request.getDepartment() : "MCA";

		// Initialize profile if ALUMNI, FACULTY, or STUDENT
		if ("ALUMNI".equals(roleStr) && alumniProfileRepository != null) {
			AlumniProfile ap = new AlumniProfile();
			ap.setUser(savedUser);
			ap.setDepartment(dept);
			alumniProfileRepository.save(ap);
		} else if ("FACULTY".equals(roleStr) && facultyRepository != null) {
			FacultyProfile fp = new FacultyProfile();
			fp.setUser(savedUser);
			fp.setDepartment(dept);
			facultyRepository.save(fp);
		} else if ("STUDENT".equals(roleStr) && studentProfileRepository != null) {
			com.alumni.management.student.entity.StudentProfile sp = new com.alumni.management.student.entity.StudentProfile();
			sp.setUser(savedUser);
			sp.setDepartment(dept);
			studentProfileRepository.save(sp);
		}

		return new UserResponseDto(savedUser.getId(), savedUser.getName(), savedUser.getEmail(), savedUser.getRole().getRoleName(), dept);
	}
}
