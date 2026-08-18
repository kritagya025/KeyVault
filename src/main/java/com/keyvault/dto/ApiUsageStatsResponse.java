package com.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiUsageStatsResponse {

    private Long apiKeyId;
    private long totalRequests;
    private long successfulRequests;
    private long failedRequests;
}
