package com.authsphere.auth_backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {   // for testing with /api/auth/protected url

    @GetMapping("/api/protected") // for testing purpose
    public String test() {
        return "Protected endpoint returning";
    }
}
// This is for testing purpose only on Google signin