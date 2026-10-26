package com.keyvault.dto;

import com.keyvault.entity.ApiUsage;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiUsageSummaryResponse {

    private Long apiKeyId;
    private String keyName;
    private String endpoint;
    private String method;
    private int statusCode;
    private boolean successful;
    private LocalDateTime timestamp;

    public static ApiUsageSummaryResponse fromEntity(ApiUsage usage) {
        Long keyId = usage.getApiKey() != null ? usage.getApiKey().getId() : null;
        String name = usage.getApiKey() != null ? usage.getApiKey().getName() : null;

        return ApiUsageSummaryResponse.builder()
                .apiKeyId(keyId)
                .keyName(name)
                .endpoint(usage.getEndpoint())
                .method(usage.getHttpMethod())
                .statusCode(usage.getStatusCode())
                .successful(usage.isSuccessful())
                .timestamp(usage.getTimestamp())
                .build();
    }
}
