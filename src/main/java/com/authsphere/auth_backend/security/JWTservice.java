package com.authsphere.auth_backend.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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

    public String extractEmail(String token){

        Jws<Claims> claims = Jwts.parser() // The payload data inside email JWS -  JSON Web Signature
                .setSigningKey(key) // use this secret key to verify signature
                .build()
                .parseClaimsJws(token); //1️⃣ Decode JWT 2️⃣ Verify signature using secret key 3️⃣ Check expiry (exp) 4️⃣ Check format 5️⃣ If valid → return Jws<Claims> 6️⃣ If invalid → throw exception

        return claims.getBody().getSubject();

        //Internally:
        //JWT is split into 3 parts:
        //header.payload.signature
        //Header + payload are re-hashed using secret key
        //If computed signature == token signature → valid
        //Then expiry time is checked
        //Then claims returned
    }
}

