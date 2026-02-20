package com.authsphere.auth_backend.Service;

import com.authsphere.auth_backend.dto.GoogleLoginRequest;
import com.authsphere.auth_backend.repository.UserRepository;
import com.authsphere.auth_backend.dto.RegisterRequest;
import com.authsphere.auth_backend.dto.LoginRequest;
import com.authsphere.auth_backend.entity.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;

import java.util.Collections;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String register(RegisterRequest request){  //User register
        if(userRepository.existsByEmail(request.getEmail())){
            throw new RuntimeException("Email already registered");
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());

        user.setPassword(passwordEncoder.encode(request.getPassword())); // encrypt password

        user.setProvider("LOCAL");

        userRepository.save(user); // save to database

        return "User registered successfully";
    }

    public String login(LoginRequest request){  //User Login
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found")); // find the user email with given parameters then can check the corresponding pwd with given pwd

        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new RuntimeException("Invalid Password");
        }

        return "Login Successful";
    }

    public String googleLogin(String idTokenString) throws Exception{
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                new GsonFactory())
                .setAudience(Collections.singletonList("Your Google Client ID"))
                .build();

        GoogleIdToken idToken = verifier.verify(idTokenString);

        if(idToken == null){
            throw new RuntimeException("Invalid Google token");
        }


        return "Google Login Successful";

    }
}
