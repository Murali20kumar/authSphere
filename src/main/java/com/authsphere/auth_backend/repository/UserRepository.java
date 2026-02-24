package com.authsphere.auth_backend.repository;

import com.authsphere.auth_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Short> {

    Optional<User> findByEmail(String email);

    //Optional<User> findByName(String name);

    boolean existsByEmail(String email);
}

