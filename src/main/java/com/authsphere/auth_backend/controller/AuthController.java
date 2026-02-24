package com.authsphere.auth_backend.controller;

import com.authsphere.auth_backend.Service.AuthService;
import com.authsphere.auth_backend.dto.GoogleLoginRequest;
import com.authsphere.auth_backend.dto.RegisterRequest;
import com.authsphere.auth_backend.dto.LoginRequest;
import org.springframework.http.ResponseEntity;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController //This class handles HTTP requests and return JSON
@RequestMapping("/api/auth") // BASE URL : http://localhost:8080/api/auth

public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService){
        this.authService = authService;
    }

    @PostMapping("/register") // POST http://localhost:8080/api/auth/register where dispatcher checks when the request is POST

    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request){ // Triggers validation from DTO annotations , if invalid -> automatic 400 response, RequestBody -> convert JSON into Registerrequest Object

        String response =  authService.register(request);

        return ResponseEntity.ok(response); // returns in HTTP response, 200, 404, 500
    }

    @PostMapping("/login")

    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request){
        String response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/google-login")  // for signing-in via Google

    public ResponseEntity<?> googleLogin (@Valid @RequestBody GoogleLoginRequest request) throws Exception {

       String response = authService.googleLogin(request.getIdToken());

        return ResponseEntity.ok(response);

    }

}
