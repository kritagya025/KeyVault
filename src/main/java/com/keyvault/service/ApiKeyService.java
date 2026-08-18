package com.keyvault.service;

import com.keyvault.config.ApiKeyGenerator;
import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.User;
import com.keyvault.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyGenerator apiKeyGenerator;

    @Transactional
    public CreateApiKeyResponse createApiKey(User user, CreateApiKeyRequest request) {
        if (request.getExpiresAt() != null && request.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Expiration date must be in the future");
        }

        String rawApiKey = apiKeyGenerator.generateRawApiKey();
        String keyHash = apiKeyGenerator.hashApiKey(rawApiKey);

        ApiKey apiKey = ApiKey.builder()
                .name(request.getName())
                .keyHash(keyHash)
                .expiresAt(request.getExpiresAt())
                .revoked(false)
                .user(user)
                .build();

        ApiKey savedKey = apiKeyRepository.save(apiKey);

        return CreateApiKeyResponse.builder()
                .id(savedKey.getId())
                .name(savedKey.getName())
                .apiKey(rawApiKey)
                .expiresAt(savedKey.getExpiresAt())
                .createdAt(savedKey.getCreatedAt())
                .revoked(savedKey.isRevoked())
                .build();
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user) {
        return apiKeyRepository.findByUserId(user.getId())
                .stream()
                .map(ApiKeyResponse::fromEntity)
                .toList();
    }
}
