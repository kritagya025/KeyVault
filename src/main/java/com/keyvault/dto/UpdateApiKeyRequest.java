package com.keyvault.dto;

import com.keyvault.entity.Permission;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateApiKeyRequest {

    @Size(min = 1, max = 100, message = "Key name must be between 1 and 100 characters")
    private String name;

    private Set<Permission> permissions;
}
