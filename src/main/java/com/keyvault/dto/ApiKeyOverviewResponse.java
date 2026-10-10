package com.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKeyOverviewResponse {

    private long totalKeys;
    private long activeKeys;
    private long revokedKeys;
    private long expiredKeys;
    private long totalRequests;
    private long successfulRequests;
    private long failedRequests;
}
