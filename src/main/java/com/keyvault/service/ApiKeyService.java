package com.keyvault.service;

import com.keyvault.config.ApiKeyGenerator;
import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.Permission;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

/**
 * Service managing the lifecycle of API keys, including generation,
 * SHA-256 hash storage, retrieval, revocation, and regeneration.
 */
@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyGenerator apiKeyGenerator;

    /**
     * Generates a new API key for the authenticated user.
     * Persists the SHA-256 hash and returns the raw key once.
     *
     * @param user the key owner
     * @param request creation request containing key name, permissions, and optional expiry
     * @return creation response with raw key emitted once
     */
    @Transactional
    public CreateApiKeyResponse createApiKey(User user, CreateApiKeyRequest request) {
        if (request.getExpiresAt() != null && request.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Expiration date must be in the future");
        }

        Set<Permission> assignedPermissions = request.getPermissions();
        if (assignedPermissions == null || assignedPermissions.isEmpty()) {
            assignedPermissions = Set.of(Permission.READ);
        }

        String rawApiKey = apiKeyGenerator.generateRawApiKey();
        String keyHash = apiKeyGenerator.hashApiKey(rawApiKey);

        ApiKey apiKey = ApiKey.builder()
                .name(request.getName())
                .keyHash(keyHash)
                .expiresAt(request.getExpiresAt())
                .revoked(false)
                .user(user)
                .permissions(assignedPermissions)
                .build();

        ApiKey savedKey = apiKeyRepository.save(apiKey);

        return CreateApiKeyResponse.builder()
                .id(savedKey.getId())
                .name(savedKey.getName())
                .apiKey(rawApiKey)
                .expiresAt(savedKey.getExpiresAt())
                .createdAt(savedKey.getCreatedAt())
                .revoked(savedKey.isRevoked())
                .permissions(savedKey.getPermissions())
                .build();
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user) {
        return apiKeyRepository.findByUserId(user.getId())
                .stream()
                .map(ApiKeyResponse::fromEntity)
                .toList();
    }

    @Transactional(readOnly = true)
    public ApiKeyResponse getApiKeyById(User user, Long id) {
        ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);
        return ApiKeyResponse.fromEntity(apiKey);
    }

    @Transactional
    public ApiKeyResponse revokeApiKey(User user, Long id) {
        ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);
        if (!apiKey.isRevoked()) {
            apiKey.setRevoked(true);
            apiKey = apiKeyRepository.save(apiKey);
        }
        return ApiKeyResponse.fromEntity(apiKey);
    }

    @Transactional
    public CreateApiKeyResponse regenerateApiKey(User user, Long id) {
        ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);

        String currentStatus = ApiKeyResponse.calculateStatus(apiKey);
        if ("REVOKED".equals(currentStatus)) {
            throw new IllegalStateException("Cannot regenerate a revoked API key");
        }

        String newRawApiKey = apiKeyGenerator.generateRawApiKey();
        String newKeyHash = apiKeyGenerator.hashApiKey(newRawApiKey);

        apiKey.setKeyHash(newKeyHash);
        ApiKey savedKey = apiKeyRepository.save(apiKey);

        return CreateApiKeyResponse.builder()
                .id(savedKey.getId())
                .name(savedKey.getName())
                .apiKey(newRawApiKey)
                .expiresAt(savedKey.getExpiresAt())
                .createdAt(savedKey.getCreatedAt())
                .revoked(savedKey.isRevoked())
                .permissions(savedKey.getPermissions())
                .build();
    }

    private ApiKey findApiKeyAndVerifyOwnership(User user, Long id) {
        ApiKey apiKey = apiKeyRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + id));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + id);
        }

        return apiKey;
    }
}
