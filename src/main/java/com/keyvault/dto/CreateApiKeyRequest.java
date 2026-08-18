package com.keyvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateApiKeyRequest {

    @NotBlank(message = "API key name cannot be blank")
    @Size(max = 100, message = "API key name cannot exceed 100 characters")
    private String name;

    private LocalDateTime expiresAt;
}
