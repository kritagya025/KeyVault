package com.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

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
}
