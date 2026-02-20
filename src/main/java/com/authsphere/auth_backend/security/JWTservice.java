package com.authsphere.auth_backend.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JWTservice { //only to generating JWT tokens( single responsibility)

    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String generateToken(String email){

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date()) // stores when token was created
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1000ms * 60 = 1 min, again * 60 = 1 hour
                .signWith(key) // takes all headers  Payload and signs them using the secret key
                .compact(); // converts everything into JWT token

        // returns generated JWT token
    }
}

