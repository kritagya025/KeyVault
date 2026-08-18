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
    }

    @Transactional(readOnly = true)
    public ApiUsageStatsResponse getUsageStats(User user, Long apiKeyId) {
        verifyApiKeyOwnership(user, apiKeyId);

        long total = apiUsageRepository.countByApiKeyId(apiKeyId);
        long successful = apiUsageRepository.countByApiKeyIdAndSuccessfulTrue(apiKeyId);
        long failed = apiUsageRepository.countByApiKeyIdAndSuccessfulFalse(apiKeyId);

        return ApiUsageStatsResponse.builder()
                .apiKeyId(apiKeyId)
                .totalRequests(total)
                .successfulRequests(successful)
                .failedRequests(failed)
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

    private void verifyApiKeyOwnership(User user, Long apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findById(apiKeyId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + apiKeyId));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + apiKeyId);
        }
    }
}
