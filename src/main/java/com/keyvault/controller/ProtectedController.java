package com.keyvault.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "4. Protected Consumer APIs", description = "Consumer endpoints authenticated via X-API-Key header with granular permission checks")
@SecurityRequirement(name = "ApiKeyAuth")
public class ProtectedController {

    @GetMapping("/hello")
    @Operation(summary = "Protected Hello Endpoint", description = "Access basic protected consumer endpoint requiring any valid API key.")
    public ResponseEntity<Map<String, String>> hello(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Hello, authenticated user!",
                "user", authentication.getName()
        ));
    }

    @GetMapping("/read")
    @PreAuthorize("hasAuthority('KEY_READ')")
    @Operation(summary = "Read Protected Endpoint", description = "Access consumer read endpoint. Requires an API key with READ permission.")
    public ResponseEntity<Map<String, String>> readData(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Read access granted",
                "user", authentication.getName()
        ));
    }

    @PostMapping("/write")
    @PreAuthorize("hasAuthority('KEY_WRITE')")
    @Operation(summary = "Write Protected Endpoint", description = "Access consumer write endpoint. Requires an API key with WRITE permission.")
    public ResponseEntity<Map<String, String>> writeData(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Write access granted",
                "user", authentication.getName()
        ));
    }
}
