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
    private final com.keyvault.repository.ApiUsageRepository apiUsageRepository;

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
        String maskedKey = apiKeyGenerator.maskApiKey(rawApiKey);

        Set<String> ipRestrictions = request.getIpRestrictions() != null
                ? new java.util.HashSet<>(request.getIpRestrictions())
                : new java.util.HashSet<>();

        com.keyvault.entity.KeyEnvironment environment = request.getEnvironment() != null
                ? request.getEnvironment()
                : com.keyvault.entity.KeyEnvironment.DEVELOPMENT;

        ApiKey apiKey = ApiKey.builder()
                .name(request.getName())
                .keyHash(keyHash)
                .maskedKey(maskedKey)
                .expiresAt(request.getExpiresAt())
                .revoked(false)
                .user(user)
                .permissions(assignedPermissions)
                .ipRestrictions(ipRestrictions)
                .environment(environment)
                .rateLimit(request.getRateLimit())
                .build();

        ApiKey savedKey = apiKeyRepository.save(apiKey);

        return toCreateResponse(savedKey, rawApiKey);
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user) {
        return getUserApiKeys(user, null, null, null);
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user, String status, String query) {
        return getUserApiKeys(user, status, query, null);
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user, String status, String query, String environment) {
        List<ApiKey> keys = apiKeyRepository.findByUserId(user.getId());

        if (status != null && !status.trim().isEmpty()) {
            String normalizedStatus = status.trim().toUpperCase();
            if (!Set.of("ACTIVE", "REVOKED", "EXPIRED").contains(normalizedStatus)) {
                throw new IllegalArgumentException("Invalid status filter: " + status + ". Allowed values: ACTIVE, REVOKED, EXPIRED");
            }
            keys = keys.stream()
                    .filter(key -> ApiKeyResponse.calculateStatus(key).equals(normalizedStatus))
                    .toList();
        }

        if (query != null && !query.trim().isEmpty()) {
            String lowerQuery = query.trim().toLowerCase();
            keys = keys.stream()
                    .filter(key -> key.getName() != null && key.getName().toLowerCase().contains(lowerQuery))
                    .toList();
        }

        if (environment != null && !environment.trim().isEmpty()) {
            String normalizedEnv = environment.trim().toUpperCase();
            com.keyvault.entity.KeyEnvironment targetEnv;
            try {
                targetEnv = com.keyvault.entity.KeyEnvironment.valueOf(normalizedEnv);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid environment filter: " + environment + ". Allowed values: DEVELOPMENT, STAGING, PRODUCTION");
            }
            keys = keys.stream()
                    .filter(key -> key.getEnvironment() == targetEnv)
                    .toList();
        }

        return keys.stream()
                .map(ApiKeyResponse::fromEntity)
                .toList();
    }

    @Transactional(readOnly = true)
    public com.keyvault.dto.ApiKeyOverviewResponse getAccountSummary(User user) {
        List<ApiKey> keys = apiKeyRepository.findByUserId(user.getId());

        long activeKeys = 0;
        long revokedKeys = 0;
        long expiredKeys = 0;
        long expiringSoonKeys = 0;
        LocalDateTime now = LocalDateTime.now();

        for (ApiKey key : keys) {
            String status = ApiKeyResponse.calculateStatus(key);
            switch (status) {
                case "ACTIVE" -> {
                    activeKeys++;
                    if (key.getExpiresAt() != null && key.getExpiresAt().isAfter(now) && java.time.Duration.between(now, key.getExpiresAt()).toDays() <= 7) {
                        expiringSoonKeys++;
                    }
                }
                case "REVOKED" -> revokedKeys++;
                case "EXPIRED" -> expiredKeys++;
            }
        }

        long totalRequests = apiUsageRepository.countByUserId(user.getId());
        long successfulRequests = apiUsageRepository.countByUserIdAndSuccessfulTrue(user.getId());
        long failedRequests = apiUsageRepository.countByUserIdAndSuccessfulFalse(user.getId());

        return com.keyvault.dto.ApiKeyOverviewResponse.builder()
                .totalKeys(keys.size())
                .activeKeys(activeKeys)
                .revokedKeys(revokedKeys)
                .expiredKeys(expiredKeys)
                .expiringSoonKeys(expiringSoonKeys)
                .totalRequests(totalRequests)
                .successfulRequests(successfulRequests)
                .failedRequests(failedRequests)
                .build();
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
     * Updates metadata (name and/or permissions) for an existing active or expired API key.
     * Revoked keys cannot be updated.
     *
     * @param user the key owner
     * @param id the API key id
     * @param request update request containing new name or permissions
     * @return updated key response
     */
    @Transactional
    public ApiKeyResponse updateApiKey(User user, Long id, com.keyvault.dto.UpdateApiKeyRequest request) {
        ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);

        if (apiKey.isRevoked()) {
            throw new IllegalStateException("Cannot update a revoked API key");
        }

        if (request.getName() != null && !request.getName().trim().isEmpty()) {
            apiKey.setName(request.getName().trim());
        }

        if (request.getPermissions() != null) {
            if (request.getPermissions().isEmpty()) {
                throw new IllegalArgumentException("API key must have at least one permission");
            }
            apiKey.setPermissions(EnumSet.copyOf(request.getPermissions()));
        }

        if (Boolean.TRUE.equals(request.getClearExpiration())) {
            apiKey.setExpiresAt(null);
        } else if (request.getExpiresAt() != null) {
            if (request.getExpiresAt().isBefore(LocalDateTime.now())) {
                throw new IllegalArgumentException("Expiration date must be in the future");
            }
            apiKey.setExpiresAt(request.getExpiresAt());
        }

        if (request.getIpRestrictions() != null) {
            apiKey.setIpRestrictions(new java.util.HashSet<>(request.getIpRestrictions()));
        }

        if (request.getEnvironment() != null) {
            apiKey.setEnvironment(request.getEnvironment());
        }

        if (Boolean.TRUE.equals(request.getClearRateLimit())) {
            apiKey.setRateLimit(null);
        } else if (request.getRateLimit() != null) {
            apiKey.setRateLimit(request.getRateLimit());
        }

        ApiKey updated = apiKeyRepository.save(apiKey);
        return ApiKeyResponse.fromEntity(updated);
    }

    /**
     * Permanently deletes an API key and cleans up its associated usage metrics.
     *
     * @param user the key owner
     * @param id the API key id
     */
    @Transactional
    public void deleteApiKey(User user, Long id) {
        ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);
        apiUsageRepository.deleteByApiKeyId(apiKey.getId());
        apiKeyRepository.delete(apiKey);
    }

    @Transactional
    public com.keyvault.dto.BulkKeyActionResponse bulkRevokeApiKeys(User user, Set<Long> keyIds) {
        if (keyIds == null || keyIds.isEmpty()) {
            throw new IllegalArgumentException("keyIds must not be empty");
        }
        List<Long> successfulIds = new java.util.ArrayList<>();
        List<Long> failedIds = new java.util.ArrayList<>();

        for (Long id : keyIds) {
            try {
                ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);
                if (!apiKey.isRevoked()) {
                    apiKey.setRevoked(true);
                    apiKeyRepository.save(apiKey);
                }
                successfulIds.add(id);
            } catch (Exception e) {
                failedIds.add(id);
            }
        }

        return com.keyvault.dto.BulkKeyActionResponse.builder()
                .requestedCount(keyIds.size())
                .processedCount(successfulIds.size())
                .successfulIds(successfulIds)
                .failedIds(failedIds)
                .message("Bulk revocation completed: " + successfulIds.size() + " succeeded, " + failedIds.size() + " failed")
                .build();
    }

    @Transactional
    public com.keyvault.dto.BulkKeyActionResponse bulkDeleteApiKeys(User user, Set<Long> keyIds) {
        if (keyIds == null || keyIds.isEmpty()) {
            throw new IllegalArgumentException("keyIds must not be empty");
        }
        List<Long> successfulIds = new java.util.ArrayList<>();
        List<Long> failedIds = new java.util.ArrayList<>();

        for (Long id : keyIds) {
            try {
                ApiKey apiKey = findApiKeyAndVerifyOwnership(user, id);
                apiUsageRepository.deleteByApiKeyId(apiKey.getId());
                apiKeyRepository.delete(apiKey);
                successfulIds.add(id);
            } catch (Exception e) {
                failedIds.add(id);
            }
        }

        return com.keyvault.dto.BulkKeyActionResponse.builder()
                .requestedCount(keyIds.size())
                .processedCount(successfulIds.size())
                .successfulIds(successfulIds)
                .failedIds(failedIds)
                .message("Bulk deletion completed: " + successfulIds.size() + " succeeded, " + failedIds.size() + " failed")
                .build();
    }

    /**
     * Issues a replacement API key with identical scopes, restrictions, and environment,
     * while giving the original key an overlapping grace period for zero-downtime rotation.
     *
     * @param user the key owner
     * @param id the API key id to rotate
     * @param request rotation options containing grace period in hours
     * @return creation response containing the newly issued key
     */
    @Transactional
    public CreateApiKeyResponse rotateApiKey(User user, Long id, com.keyvault.dto.RotateApiKeyRequest request) {
        ApiKey oldKey = findApiKeyAndVerifyOwnership(user, id);

        String currentStatus = ApiKeyResponse.calculateStatus(oldKey);
        if ("REVOKED".equals(currentStatus)) {
            throw new IllegalStateException("Cannot rotate a revoked API key");
        }

        int graceHours = (request != null && request.getGracePeriodHours() != null)
                ? request.getGracePeriodHours()
                : 24;

        LocalDateTime oldKeyExpiry = LocalDateTime.now().plusHours(graceHours);
        if (oldKey.getExpiresAt() == null || oldKey.getExpiresAt().isAfter(oldKeyExpiry)) {
            oldKey.setExpiresAt(oldKeyExpiry);
            apiKeyRepository.save(oldKey);
        }

        String newRawApiKey = apiKeyGenerator.generateRawApiKey();
        String newKeyHash = apiKeyGenerator.hashApiKey(newRawApiKey);
        String newMaskedKey = apiKeyGenerator.maskApiKey(newRawApiKey);

        ApiKey newKey = ApiKey.builder()
                .name(oldKey.getName())
                .keyHash(newKeyHash)
                .maskedKey(newMaskedKey)
                .expiresAt(null)
                .revoked(false)
                .user(user)
                .permissions(new java.util.HashSet<>(oldKey.getPermissions()))
                .ipRestrictions(new java.util.HashSet<>(oldKey.getIpRestrictions()))
                .environment(oldKey.getEnvironment())
                .rateLimit(oldKey.getRateLimit())
                .build();

        ApiKey savedNewKey = apiKeyRepository.save(newKey);
        return toCreateResponse(savedNewKey, newRawApiKey);
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
        String newMaskedKey = apiKeyGenerator.maskApiKey(newRawApiKey);

        apiKey.setKeyHash(newKeyHash);
        apiKey.setMaskedKey(newMaskedKey);
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
                .maskedKey(apiKey.getMaskedKey())
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .lastUsedAt(apiKey.getLastUsedAt())
                .revoked(apiKey.isRevoked())
                .permissions(apiKey.getPermissions())
                .ipRestrictions(apiKey.getIpRestrictions())
                .environment(apiKey.getEnvironment())
                .rateLimit(apiKey.getRateLimit())
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
