package com.eleftq.sec.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public ResponseEntity<Map<String, String>> allAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Public Content.");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('ROLE_USER') or hasAuthority('ROLE_MODERATOR')")
    public ResponseEntity<Map<String, String>> userAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "User Content.");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Map<String, String>> adminAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Admin Board.");
        return ResponseEntity.ok(response);
    }
}
