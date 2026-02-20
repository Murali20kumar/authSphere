package com.authsphere.auth_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Short id;   // SMALLINT VALUE (-32768 - 32767)

    @Column(nullable = false, length = 75)
    private String name;

    @Column(nullable = false, unique = true, length = 120)
    private String email;

    @Column(length = 255)
    private String password;

    @Column(nullable = false, length = 20)
    private String provider = "LOCAL";

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
