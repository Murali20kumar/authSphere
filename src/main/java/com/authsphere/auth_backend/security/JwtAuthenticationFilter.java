package com.authsphere.auth_backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.util.Collections;
import java.io.IOException;

//https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html
@Component // Create an Object(bean) for this class
public class JwtAuthenticationFilter extends OncePerRequestFilter { // runs once per HTTP request before it's hitting the controller

    private final JWTservice jwtService;

    public JwtAuthenticationFilter(JWTservice jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("Filter is running");

        String authHeader = request.getHeader("Authorization"); // get Authorization header

        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // Bearer means : Whoever bears (holds) this token is authorized. it doesn't include email/password
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // why 7? cause "Bearer " it takes 7 space so removes that and takes token

        try {
            String email = jwtService.extractEmail(token); // Get the email from the given token via Payload

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken( //When a user logs in, this token is created to hold the raw username (principal) and password (credentials)
                    email, // Object principal
                    null,  //Object credentials (no need of pwd)
                    Collections.emptyList() // Collection < ? extends GrantedAuthority> authorities ( no roles like admin / user)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication); // Once authenticated, the token is stored in the SecurityContextHolder, allowing the application to identify the current user across different requests
        } catch (Exception e) {
            e.printStackTrace();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); //401 Unauthorized and stops controlleer
            return;
        }

        filterChain.doFilter(request, response);
    }
}