package com.authsphere.auth_backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name="pwd_reset_tokens")
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private short id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiryTime;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;


    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
