package com.keyvault.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/protected")
public class ProtectedController {

    @GetMapping("/hello")
    public ResponseEntity<Map<String, String>> hello(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Hello, authenticated user!",
                "user", authentication.getName()
        ));
    }

    @GetMapping("/read")
    @PreAuthorize("hasAuthority('KEY_READ')")
    public ResponseEntity<Map<String, String>> readData(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Read access granted",
                "user", authentication.getName()
        ));
    }

    @PostMapping("/write")
    @PreAuthorize("hasAuthority('KEY_WRITE')")
    public ResponseEntity<Map<String, String>> writeData(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Write access granted",
                "user", authentication.getName()
        ));
    }
}
