package com.alumni.management.user.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alumni.management.user.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

//	We take email for unique authentication in login we
//	normally use email and password that why	 
	Optional<User> findByEmail(String email);
	Optional<User> findByEmailIgnoreCase(String email);
	Optional<User> findByUniversityNumber(String universityNumber);
	
	List<User> findByRole_RoleName(String roleName);
	List<User> findByNameContainingIgnoreCase(String name);
	Optional<User> findByFirebaseUid(String firebaseUid);
	

}
