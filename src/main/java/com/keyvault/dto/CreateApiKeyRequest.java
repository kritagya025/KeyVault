package com.keyvault.dto;

import com.keyvault.entity.Permission;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
public class CreateApiKeyRequest {

    @NotBlank(message = "API key name cannot be blank")
    @Size(max = 100, message = "API key name cannot exceed 100 characters")
    private String name;

    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;

    private Set<String> tags;

    private LocalDateTime expiresAt;

    private Set<Permission> permissions;

    private Set<String> ipRestrictions;

    private com.keyvault.entity.KeyEnvironment environment;

    @jakarta.validation.constraints.Positive(message = "Rate limit must be greater than 0")
    private Integer rateLimit;
}
