package com.keyvault.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Future;
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
public class DuplicateApiKeyRequest {

    @Size(max = 100, message = "API key name cannot exceed 100 characters")
    @Schema(description = "Optional custom name for the duplicated key. Defaults to 'Copy of {original.name}'.", example = "Service Worker Key")
    private String name;

    @Future(message = "Expiration date must be in the future")
    @Schema(description = "Optional expiration date for the duplicated key. If omitted, adopts the expiration of the original key if in the future, or null.", example = "2027-01-01T00:00:00")
    private LocalDateTime expiresAt;
}
