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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Service managing the lifecycle of API keys, including generation,
 * SHA-256 hash storage, retrieval, revocation, and regeneration.
 */
@Service
@RequiredArgsConstructor
public class ApiKeyService {

    /**
     * Validity window granted to a regenerated key whose original window
     * cannot be derived (defensive fallback for anomalous stored data).
     */
    private static final Duration FALLBACK_REGENERATED_LIFETIME = Duration.ofDays(30);

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

        Set<Permission> requestedPermissions = request.getPermissions();
        Set<Permission> assignedPermissions = (requestedPermissions == null || requestedPermissions.isEmpty())
                ? EnumSet.of(Permission.READ)
                : EnumSet.copyOf(requestedPermissions);

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

        return toCreateResponse(savedKey, rawApiKey);
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

    /**
     * Issues a fresh raw key for an existing ACTIVE or EXPIRED key, replacing the stored hash.
     * An EXPIRED key is brought back to ACTIVE by re-anchoring its original validity window
     * from the moment of regeneration, so the newly issued key is immediately usable.
     * Keys without an expiry, and keys that have not expired yet, keep their current window.
     *
     * @param user the key owner
     * @param id the API key id
     * @return creation response with the new raw key emitted once
     * @throws IllegalStateException if the key has been revoked
     */
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
        if ("EXPIRED".equals(currentStatus)) {
            apiKey.setExpiresAt(LocalDateTime.now().plus(originalLifetimeOf(apiKey)));
        }

        ApiKey savedKey = apiKeyRepository.save(apiKey);

        return toCreateResponse(savedKey, newRawApiKey);
    }

    /**
     * Derives how long a key was originally valid for, falling back to a fixed
     * window when the stored timestamps do not yield a positive duration.
     */
    private Duration originalLifetimeOf(ApiKey apiKey) {
        if (apiKey.getCreatedAt() == null || apiKey.getExpiresAt() == null) {
            return FALLBACK_REGENERATED_LIFETIME;
        }
        Duration lifetime = Duration.between(apiKey.getCreatedAt(), apiKey.getExpiresAt());
        return lifetime.isNegative() || lifetime.isZero() ? FALLBACK_REGENERATED_LIFETIME : lifetime;
    }

    private CreateApiKeyResponse toCreateResponse(ApiKey apiKey, String rawApiKey) {
        return CreateApiKeyResponse.builder()
                .id(apiKey.getId())
                .name(apiKey.getName())
                .apiKey(rawApiKey)
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .revoked(apiKey.isRevoked())
                .permissions(apiKey.getPermissions())
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
