package com.authsphere.auth_backend.Service;

import com.authsphere.auth_backend.dto.GoogleLoginRequest;
import com.authsphere.auth_backend.entity.PasswordResetToken;
import com.authsphere.auth_backend.repository.PasswordResetTokenRepository;
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
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTservice jwTservice;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTservice jwTservice, PasswordResetTokenRepository passwordResetTokenRepository, EmailService emailService){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwTservice = jwTservice;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailService = emailService;
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
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder( //Decode JWT, Read header, download public keys, verify signatire, check expiry, check audience if matches my app
                new NetHttpTransport(), //to make HTTP requests i.e to fetch Google keys.
                new GsonFactory()) // to parse JSON inside the token , i.e to decode the token.
                .setAudience(Collections.singletonList("551473793625-877iqqor90l9nbqvrhhm3mgtqb7s0joh.apps.googleusercontent.com")) //If someone sends token generated for another app then verification fails.
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

        GoogleIdToken.Payload payload1 = GoogleIdToken.parse(
                new GsonFactory(),
                idTokenString
        ).getPayload();

        System.out.println("AUD from token: " + payload1.getAudience());
        System.out.println("ISS from token: " + payload1.getIssuer());
        
        String token = jwTservice.generateToken(email);
        return token;
    }


    //Forgot password method
    @Transactional
    public  String forgotPassword(String email){

        User user = userRepository.findByEmail(email).orElse(null);

        if(user == null){
            return "If the mail exists, a reset link has been sent";
        }

        if("GOOGLE".equals(user.getProvider())){
            //throw new RuntimeException("Password reset is not for Google Login");
            String s = "Password reset is not for Google Login";
            return s;
        }

        String result = "";

        if(user != null){

            passwordResetTokenRepository.deleteByUserId(user.getId()); // to delete old saved tokens

            String token = UUID.randomUUID().toString();  //Generate random token , java.lang.Object
            //java.util.UUID , A class that represents an immutable universally unique identifier (UUID). A UUID represents a 128-bit value

            PasswordResetToken resetToken = new PasswordResetToken();
            resetToken.setToken(token);
            resetToken.setUser(user);

            resetToken.setExpiryTime(LocalDateTime.now().plusMinutes(15)); // now token is valid for 15 mins

            passwordResetTokenRepository.save(resetToken);

            System.out.println("Reset Token :" + token);

            result = token; // In real time we send link to mail or OTP via mail or SMS

            emailService.sendPasswordResetEmail(user.getEmail(), token);
        }


        return result ;
    }

    //To Reset-Password

    @Transactional
    public String resetPassword (String token, String newPassword){

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token).orElseThrow(()-> new RuntimeException("Invalid token"));

        if(resetToken.getExpiryTime().isBefore(LocalDateTime.now()))   throw new RuntimeException("Reset token expired");

        User user = resetToken.getUser();

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenRepository.delete(resetToken);

        return "Reset password successfully";
    }
}
