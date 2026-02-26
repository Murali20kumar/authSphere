package com.authsphere.auth_backend.repository;

import com.authsphere.auth_backend.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Short> {

    Optional<PasswordResetToken> findByToken(String token); // Optional to avoid nullpointer exception, if null means it returns empty(), so we can use .orElseThrow()

    void deleteByUserId(Short userId);
}
