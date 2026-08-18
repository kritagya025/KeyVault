package com.keyvault.dto;

import com.keyvault.entity.ApiKey;
import com.keyvault.entity.Permission;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

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
    private String status;
    private Set<Permission> permissions;

    public static ApiKeyResponse fromEntity(ApiKey apiKey) {
        return ApiKeyResponse.builder()
                .id(apiKey.getId())
                .name(apiKey.getName())
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .revoked(apiKey.isRevoked())
                .status(calculateStatus(apiKey))
                .permissions(apiKey.getPermissions())
                .build();
    }

    public static String calculateStatus(ApiKey apiKey) {
        if (apiKey.isRevoked()) {
            return "REVOKED";
        }
        if (apiKey.getExpiresAt() != null && apiKey.getExpiresAt().isBefore(LocalDateTime.now())) {
            return "EXPIRED";
        }
        return "ACTIVE";
    }
}
