package com.keyvault.dto;

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
public class CreateApiKeyResponse {

    private Long id;
    private String name;
    private String apiKey;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private boolean revoked;
    private Set<Permission> permissions;
}
