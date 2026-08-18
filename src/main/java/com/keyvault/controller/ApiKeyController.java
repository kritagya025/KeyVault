package com.keyvault.controller;

import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.ApiUsageStatsResponse;
import com.keyvault.dto.ApiUsageSummaryResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.User;
import com.keyvault.repository.UserRepository;
import com.keyvault.service.ApiKeyService;
import com.keyvault.service.ApiUsageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
    private final ApiUsageService apiUsageService;
    private final UserRepository userRepository;

    @PostMapping
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
            Authentication authentication,
            @Valid @RequestBody CreateApiKeyRequest request
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    public ResponseEntity<List<ApiKeyResponse>> getUserApiKeys(Authentication authentication) {
        User user = getUser(authentication);
        List<ApiKeyResponse> response = apiKeyService.getUserApiKeys(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiKeyResponse> getApiKeyById(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.getApiKeyById(user, id);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{id}/revoke")
    public ResponseEntity<ApiKeyResponse> revokeApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.revokeApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/regenerate")
    public ResponseEntity<CreateApiKeyResponse> regenerateApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage")
    public ResponseEntity<ApiUsageStatsResponse> getUsageStats(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiUsageStatsResponse response = apiUsageService.getUsageStats(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage/recent")
    public ResponseEntity<List<ApiUsageSummaryResponse>> getRecentUsage(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        List<ApiUsageSummaryResponse> response = apiUsageService.getRecentUsage(user, id);
        return ResponseEntity.ok(response);
    }

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName()).orElseThrow();
    }
}
