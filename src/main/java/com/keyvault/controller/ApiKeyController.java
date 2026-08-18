package com.keyvault.controller;

import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.ApiUsageStatsResponse;
import com.keyvault.dto.ApiUsageSummaryResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.UserRepository;
import com.keyvault.service.ApiKeyService;
import com.keyvault.service.ApiUsageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "3. API Key Management & Usage", description = "API key generation, lifecycle management, and usage statistics")
@SecurityRequirement(name = "BearerAuth")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final ApiUsageService apiUsageService;
    private final UserRepository userRepository;

    @PostMapping
    @Operation(summary = "Generate API Key", description = "Generate a new API key with optional expiration date and specified permissions (READ, WRITE). Returns the raw API key ONCE.")
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
            Authentication authentication,
            @Valid @RequestBody CreateApiKeyRequest request
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "List User API Keys", description = "Retrieve metadata and permissions for all API keys owned by the authenticated user.")
    public ResponseEntity<List<ApiKeyResponse>> getUserApiKeys(Authentication authentication) {
        User user = getUser(authentication);
        List<ApiKeyResponse> response = apiKeyService.getUserApiKeys(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get API Key Details", description = "Retrieve metadata, permissions, and derived status for a specific API key.")
    public ResponseEntity<ApiKeyResponse> getApiKeyById(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.getApiKeyById(user, id);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{id}/revoke")
    @Operation(summary = "Revoke API Key", description = "Revoke an API key immediately. Revoked keys cannot be regenerated or used for authentication.")
    public ResponseEntity<ApiKeyResponse> revokeApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.revokeApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/regenerate")
    @Operation(summary = "Regenerate API Key", description = "Regenerate an ACTIVE or EXPIRED API key. Replaces old hash with a new key and returns the raw key ONCE.")
    public ResponseEntity<CreateApiKeyResponse> regenerateApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage")
    @Operation(summary = "Get API Key Usage Statistics", description = "Retrieve aggregate request statistics (total, successful, failed) for an API key owned by the user.")
    public ResponseEntity<ApiUsageStatsResponse> getUsageStats(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiUsageStatsResponse response = apiUsageService.getUsageStats(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage/recent")
    @Operation(summary = "Get Recent API Key Usage Logs", description = "Retrieve up to 10 recent usage records (endpoint, method, status code, timestamp) for an API key owned by the user.")
    public ResponseEntity<List<ApiUsageSummaryResponse>> getRecentUsage(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        List<ApiUsageSummaryResponse> response = apiUsageService.getRecentUsage(user, id);
        return ResponseEntity.ok(response);
    }

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }
}
