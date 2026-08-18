package com.keyvault.dto;

import com.keyvault.entity.ApiKey;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKeyResponse {

    private Long id;
    private String name;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private boolean revoked;

    public static ApiKeyResponse fromEntity(ApiKey apiKey) {
        return ApiKeyResponse.builder()
                .id(apiKey.getId())
                .name(apiKey.getName())
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .revoked(apiKey.isRevoked())
                .build();
    }
}
