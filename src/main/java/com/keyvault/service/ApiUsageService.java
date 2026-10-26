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
        return getPaginatedUsage(user, apiKeyId, successful, null, null, pageable);
    }

    @Transactional(readOnly = true)
    public org.springframework.data.domain.Page<ApiUsageSummaryResponse> getPaginatedUsage(
            User user,
            Long apiKeyId,
            Boolean successful,
            String httpMethod,
            String endpoint,
            org.springframework.data.domain.Pageable pageable
    ) {
        return getPaginatedUsage(user, apiKeyId, successful, httpMethod, endpoint, null, null, pageable);
    }

    @Transactional(readOnly = true)
    public org.springframework.data.domain.Page<ApiUsageSummaryResponse> getPaginatedUsage(
            User user,
            Long apiKeyId,
            Boolean successful,
            String httpMethod,
            String endpoint,
            java.time.LocalDateTime startDate,
            java.time.LocalDateTime endDate,
            org.springframework.data.domain.Pageable pageable
    ) {
        verifyApiKeyOwnership(user, apiKeyId);

        boolean hasMethod = httpMethod != null && !httpMethod.trim().isEmpty();
        boolean hasEndpoint = endpoint != null && !endpoint.trim().isEmpty();
        boolean hasDateFilter = startDate != null || endDate != null;

        org.springframework.data.domain.Page<ApiUsage> page;

        if (hasMethod || hasEndpoint || hasDateFilter) {
            org.springframework.data.jpa.domain.Specification<ApiUsage> spec = (root, query, cb) -> {
                java.util.List<jakarta.persistence.criteria.Predicate> predicates = new java.util.ArrayList<>();
                predicates.add(cb.equal(root.get("apiKey").get("id"), apiKeyId));

                if (successful != null) {
                    predicates.add(cb.equal(root.get("successful"), successful));
                }

                if (hasMethod) {
                    predicates.add(cb.equal(cb.upper(root.get("httpMethod")), httpMethod.trim().toUpperCase()));
                }

                if (hasEndpoint) {
                    predicates.add(cb.like(cb.lower(root.get("endpoint")), "%" + endpoint.trim().toLowerCase() + "%"));
                }

                if (startDate != null) {
                    predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), startDate));
                }

                if (endDate != null) {
                    predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), endDate));
                }

                return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
            };
            page = apiUsageRepository.findAll(spec, pageable);
        } else if (successful != null) {
            page = apiUsageRepository.findByApiKeyIdAndSuccessful(apiKeyId, successful, pageable);
        } else {
            page = apiUsageRepository.findByApiKeyId(apiKeyId, pageable);
        }

        return page.map(ApiUsageSummaryResponse::fromEntity);
    }

    @Transactional
    public int clearUsageLogs(User user, Long apiKeyId, java.time.LocalDateTime beforeDate) {
        verifyApiKeyOwnership(user, apiKeyId);
        if (beforeDate != null) {
            return apiUsageRepository.deleteByApiKeyIdAndTimestampBefore(apiKeyId, beforeDate);
        } else {
            return apiUsageRepository.deleteByApiKeyId(apiKeyId);
        }
    }

    @Transactional(readOnly = true)
    public byte[] exportUsageLogsAsCsv(User user, Long apiKeyId) {
        verifyApiKeyOwnership(user, apiKeyId);
        List<ApiUsage> logs = apiUsageRepository.findByApiKeyIdOrderByTimestampDesc(apiKeyId);

        StringBuilder csv = new StringBuilder();
        csv.append("Timestamp,HTTP Method,Endpoint,Status Code,Success\r\n");

        for (ApiUsage log : logs) {
            csv.append(escapeCsv(log.getTimestamp() != null ? log.getTimestamp().toString() : "")).append(",")
               .append(escapeCsv(log.getHttpMethod())).append(",")
               .append(escapeCsv(log.getEndpoint())).append(",")
               .append(log.getStatusCode()).append(",")
               .append(log.isSuccessful()).append("\r\n");
        }

        return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    @Transactional(readOnly = true)
    public ApiUsageStatsResponse getAccountUsageStats(User user) {
        long total = apiUsageRepository.countByUserId(user.getId());
        long successful = apiUsageRepository.countByUserIdAndSuccessfulTrue(user.getId());
        long failed = apiUsageRepository.countByUserIdAndSuccessfulFalse(user.getId());

        java.util.Map<String, Long> requestsByEndpoint = new java.util.LinkedHashMap<>();
        for (com.keyvault.dto.EndpointUsageCount count : apiUsageRepository.countRequestsByEndpointForUser(user.getId())) {
            requestsByEndpoint.put(count.getEndpoint(), count.getCount());
        }

        return ApiUsageStatsResponse.builder()
                .apiKeyId(null)
                .totalRequests(total)
                .successfulRequests(successful)
                .failedRequests(failed)
                .requestsByEndpoint(requestsByEndpoint)
                .build();
    }

    @Transactional(readOnly = true)
    public List<ApiUsageSummaryResponse> getAccountRecentUsage(User user) {
        return apiUsageRepository.findRecentByUserId(user.getId(), org.springframework.data.domain.PageRequest.of(0, 10))
                .stream()
                .map(ApiUsageSummaryResponse::fromEntity)
                .toList();
    }

    @Transactional(readOnly = true)
    public org.springframework.data.domain.Page<ApiUsageSummaryResponse> getAccountPaginatedUsage(
            User user,
            Long apiKeyId,
            Boolean successful,
            String httpMethod,
            String endpoint,
            java.time.LocalDateTime startDate,
            java.time.LocalDateTime endDate,
            org.springframework.data.domain.Pageable pageable
    ) {
        if (apiKeyId != null) {
            verifyApiKeyOwnership(user, apiKeyId);
        }

        boolean hasMethod = httpMethod != null && !httpMethod.trim().isEmpty();
        boolean hasEndpoint = endpoint != null && !endpoint.trim().isEmpty();
        boolean hasDateFilter = startDate != null || endDate != null;

        org.springframework.data.jpa.domain.Specification<ApiUsage> spec = (root, query, cb) -> {
            java.util.List<jakarta.persistence.criteria.Predicate> predicates = new java.util.ArrayList<>();
            predicates.add(cb.equal(root.get("apiKey").get("user").get("id"), user.getId()));

            if (apiKeyId != null) {
                predicates.add(cb.equal(root.get("apiKey").get("id"), apiKeyId));
            }

            if (successful != null) {
                predicates.add(cb.equal(root.get("successful"), successful));
            }

            if (hasMethod) {
                predicates.add(cb.equal(cb.upper(root.get("httpMethod")), httpMethod.trim().toUpperCase()));
            }

            if (hasEndpoint) {
                predicates.add(cb.like(cb.lower(root.get("endpoint")), "%" + endpoint.trim().toLowerCase() + "%"));
            }

            if (startDate != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), startDate));
            }

            if (endDate != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), endDate));
            }

            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };

        return apiUsageRepository.findAll(spec, pageable).map(ApiUsageSummaryResponse::fromEntity);
    }

    @Transactional(readOnly = true)
    public byte[] exportAccountUsageLogsAsCsv(User user) {
        List<ApiUsage> logs = apiUsageRepository.findByUserIdOrderByTimestampDesc(user.getId());

        StringBuilder csv = new StringBuilder();
        csv.append("Timestamp,Key ID,Key Name,HTTP Method,Endpoint,Status Code,Success\r\n");

        for (ApiUsage log : logs) {
            String keyIdStr = log.getApiKey() != null && log.getApiKey().getId() != null ? String.valueOf(log.getApiKey().getId()) : "";
            String keyNameStr = log.getApiKey() != null && log.getApiKey().getName() != null ? log.getApiKey().getName() : "";

            csv.append(escapeCsv(log.getTimestamp() != null ? log.getTimestamp().toString() : "")).append(",")
               .append(keyIdStr).append(",")
               .append(escapeCsv(keyNameStr)).append(",")
               .append(escapeCsv(log.getHttpMethod())).append(",")
               .append(escapeCsv(log.getEndpoint())).append(",")
               .append(log.getStatusCode()).append(",")
               .append(log.isSuccessful()).append("\r\n");
        }

        return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private String escapeCsv(String val) {
        if (val == null) {
            return "";
        }
        if (val.contains(",") || val.contains("\"") || val.contains("\n") || val.contains("\r")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return val;
    }

    private void verifyApiKeyOwnership(User user, Long apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findById(apiKeyId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + apiKeyId));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + apiKeyId);
        }
    }
}
