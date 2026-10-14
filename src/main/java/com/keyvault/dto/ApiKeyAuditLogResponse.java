package com.keyvault.dto;

import com.keyvault.entity.ApiKeyAuditLog;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKeyAuditLogResponse {

    private Long id;
    private Long apiKeyId;
    private String keyName;
    private String action;
    private String details;
    private LocalDateTime timestamp;

    public static ApiKeyAuditLogResponse fromEntity(ApiKeyAuditLog log) {
        return ApiKeyAuditLogResponse.builder()
                .id(log.getId())
                .apiKeyId(log.getApiKeyId())
                .keyName(log.getKeyName())
                .action(log.getAction())
                .details(log.getDetails())
                .timestamp(log.getTimestamp())
                .build();
    }
}
