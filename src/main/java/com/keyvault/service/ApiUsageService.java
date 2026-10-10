package com.keyvault.service;

import com.keyvault.dto.ApiUsageStatsResponse;
import com.keyvault.dto.ApiUsageSummaryResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.ApiUsage;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.ApiKeyRepository;
import com.keyvault.repository.ApiUsageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ApiUsageService {

    private final ApiUsageRepository apiUsageRepository;
    private final ApiKeyRepository apiKeyRepository;

    @Transactional
    public void recordUsage(ApiKey apiKey, String endpoint, String httpMethod, int statusCode, boolean successful) {
        ApiUsage usage = ApiUsage.builder()
                .apiKey(apiKey)
                .endpoint(endpoint)
                .httpMethod(httpMethod)
                .statusCode(statusCode)
                .successful(successful)
                .build();

        apiUsageRepository.save(usage);

        if (apiKey.getId() != null) {
            java.time.LocalDateTime now = java.time.LocalDateTime.now();
            apiKeyRepository.updateLastUsedAt(apiKey.getId(), now);
            apiKey.setLastUsedAt(now);
        }
    }

    @Transactional(readOnly = true)
    public ApiUsageStatsResponse getUsageStats(User user, Long apiKeyId) {
        verifyApiKeyOwnership(user, apiKeyId);

        long total = apiUsageRepository.countByApiKeyId(apiKeyId);
        long successful = apiUsageRepository.countByApiKeyIdAndSuccessfulTrue(apiKeyId);
        long failed = apiUsageRepository.countByApiKeyIdAndSuccessfulFalse(apiKeyId);

        java.util.Map<String, Long> requestsByEndpoint = new java.util.LinkedHashMap<>();
        for (com.keyvault.dto.EndpointUsageCount count : apiUsageRepository.countRequestsByEndpoint(apiKeyId)) {
            requestsByEndpoint.put(count.getEndpoint(), count.getCount());
        }

        return ApiUsageStatsResponse.builder()
                .apiKeyId(apiKeyId)
                .totalRequests(total)
                .successfulRequests(successful)
                .failedRequests(failed)
                .requestsByEndpoint(requestsByEndpoint)
                .build();
    }

    @Transactional(readOnly = true)
    public List<ApiUsageSummaryResponse> getRecentUsage(User user, Long apiKeyId) {
        verifyApiKeyOwnership(user, apiKeyId);

        return apiUsageRepository.findTop10ByApiKeyIdOrderByTimestampDesc(apiKeyId)
                .stream()
                .map(ApiUsageSummaryResponse::fromEntity)
                .toList();
    }

    @Transactional(readOnly = true)
    public org.springframework.data.domain.Page<ApiUsageSummaryResponse> getPaginatedUsage(
            User user,
            Long apiKeyId,
            Boolean successful,
            org.springframework.data.domain.Pageable pageable
    ) {
        verifyApiKeyOwnership(user, apiKeyId);

        org.springframework.data.domain.Page<ApiUsage> page;
        if (successful != null) {
            page = apiUsageRepository.findByApiKeyIdAndSuccessful(apiKeyId, successful, pageable);
        } else {
            page = apiUsageRepository.findByApiKeyId(apiKeyId, pageable);
        }

        return page.map(ApiUsageSummaryResponse::fromEntity);
    }

    private void verifyApiKeyOwnership(User user, Long apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findById(apiKeyId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + apiKeyId));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + apiKeyId);
        }
    }
}
