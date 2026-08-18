package com.keyvault.controller;

import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.User;
import com.keyvault.repository.UserRepository;
import com.keyvault.service.ApiKeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/keys")
@RequiredArgsConstructor
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final UserRepository userRepository;

    @PostMapping
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
            @Valid @RequestBody CreateApiKeyRequest request,
            Authentication authentication
    ) {
        User authenticatedUser = getAuthenticatedUser(authentication);
        CreateApiKeyResponse response = apiKeyService.createApiKey(authenticatedUser, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    public ResponseEntity<List<ApiKeyResponse>> listApiKeys(Authentication authentication) {
        User authenticatedUser = getAuthenticatedUser(authentication);
        List<ApiKeyResponse> responses = apiKeyService.getUserApiKeys(authenticatedUser);
        return ResponseEntity.ok(responses);
    }

    private User getAuthenticatedUser(Authentication authentication) {
        String email = authentication.getName();
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Authenticated user not found: " + email));
    }
}
