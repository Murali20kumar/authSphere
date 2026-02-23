package com.authsphere.auth_backend.Service;

import com.authsphere.auth_backend.dto.GoogleLoginRequest;
import com.authsphere.auth_backend.repository.UserRepository;
import com.authsphere.auth_backend.dto.RegisterRequest;
import com.authsphere.auth_backend.dto.LoginRequest;
import com.authsphere.auth_backend.entity.User;
import com.authsphere.auth_backend.security.JWTservice;
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
    private final JWTservice jwTservice;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTservice jwTservice){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwTservice = jwTservice;
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

        String token = jwTservice.generateToken(user.getEmail());
        return token;
    }

    public String googleLogin(String idTokenString) throws Exception{
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(), //to make HTTP requests i.e to fetch Google keys.
                new GsonFactory()) // to parse JSON inside the token , i.e to decode the token.
                .setAudience(Collections.singletonList("Your Google Client ID")) //If someone sends token generated for another app then verification fails.
                .build();

        GoogleIdToken idToken = verifier.verify(idTokenString);

        if(idToken == null){
            throw new RuntimeException("Invalid Google token");
        }

        GoogleIdToken.Payload payload = idToken.getPayload(); // payload contains email,name, GUser ID, expiry time

        String email = payload.getEmail();
        String name = (String) payload.get("name");

        User user = userRepository.findByEmail(email).orElse(null);

        if(user == null){
            user = new User();
            user.setEmail(email);
            user.setName(name);
            user.setProvider("GOOGLE");

            userRepository.save(user);
        }
        
        String token = jwTservice.generateToken(email);
        return token;
    }
}
