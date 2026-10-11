package com.keyvault.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RotateApiKeyRequest {

    @Min(value = 1, message = "Grace period must be at least 1 hour")
    @Max(value = 720, message = "Grace period cannot exceed 720 hours (30 days)")
    @Builder.Default
    private Integer gracePeriodHours = 24;
}
