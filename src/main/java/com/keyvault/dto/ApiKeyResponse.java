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
    private String maskedKey;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
    private boolean revoked;
    private String status;
    private Set<Permission> permissions;
    private Set<String> ipRestrictions;
    private com.keyvault.entity.KeyEnvironment environment;
    private boolean expiringSoon;
    private Long daysUntilExpiration;
    private Integer rateLimit;

    public static ApiKeyResponse fromEntity(ApiKey apiKey) {
        boolean isExpiringSoon = false;
        Long daysRemaining = null;
        if (apiKey.getExpiresAt() != null) {
            LocalDateTime now = LocalDateTime.now();
            long days = java.time.Duration.between(now, apiKey.getExpiresAt()).toDays();
            daysRemaining = days;
            if (!apiKey.isRevoked() && apiKey.getExpiresAt().isAfter(now) && days <= 7) {
                isExpiringSoon = true;
            }
        }

        return ApiKeyResponse.builder()
                .id(apiKey.getId())
                .name(apiKey.getName())
                .maskedKey(apiKey.getMaskedKey())
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .lastUsedAt(apiKey.getLastUsedAt())
                .revoked(apiKey.isRevoked())
                .status(calculateStatus(apiKey))
                .permissions(apiKey.getPermissions())
                .ipRestrictions(apiKey.getIpRestrictions())
                .environment(apiKey.getEnvironment())
                .expiringSoon(isExpiringSoon)
                .daysUntilExpiration(daysRemaining)
                .rateLimit(apiKey.getRateLimit())
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
