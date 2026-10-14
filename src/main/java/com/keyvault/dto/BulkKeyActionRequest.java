package com.keyvault.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BulkKeyActionRequest {

    @NotEmpty(message = "keyIds list must not be empty")
    private Set<Long> keyIds;
}
