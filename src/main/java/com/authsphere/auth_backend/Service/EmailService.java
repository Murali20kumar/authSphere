package com.authsphere.auth_backend.Service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender){
        this.mailSender = mailSender;
    }

    public void sendPasswordResetEmail(String toEmail, String token){

        String resetLink = "http://localhost:3000/reset-password?token=" + token;

        SimpleMailMessage message =  new SimpleMailMessage();

        message.setTo(toEmail);
        message.setSubject("Password Reset Request");
        message.setText("Click the link to reset your password :\n" + resetLink);

        mailSender.send(message);
    }
}
