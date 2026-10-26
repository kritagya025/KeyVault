package com.keyvault.dto;

import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RenewApiKeyRequest {

    @Min(value = 1, message = "Extension days must be at least 1")
    private Integer extensionDays;

    private LocalDateTime newExpiresAt;
}
