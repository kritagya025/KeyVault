package com.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BulkKeyActionResponse {

    private int requestedCount;
    private int processedCount;
    private List<Long> successfulIds;
    private List<Long> failedIds;
    private String message;
}
