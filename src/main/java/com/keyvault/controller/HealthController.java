package com.keyvault.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/health")
@Tag(name = "0. Health Check", description = "Public health monitoring endpoint")
public class HealthController {

    @GetMapping
    @Operation(summary = "Health Check Endpoint", description = "Returns service health status UP.")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "message", "KeyVault API is running"
        ));
    }

    @GetMapping("/metrics")
    @Operation(summary = "System Operational Metrics", description = "Returns JVM memory statistics, processor count, active thread count, and uptime.")
    public ResponseEntity<com.keyvault.dto.SystemMetricsResponse> getMetrics() {
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        long uptime = java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime() / 1000;

        return ResponseEntity.ok(com.keyvault.dto.SystemMetricsResponse.builder()
                .status("UP")
                .uptimeSeconds(uptime)
                .totalMemoryBytes(totalMemory)
                .freeMemoryBytes(freeMemory)
                .usedMemoryBytes(usedMemory)
                .availableProcessors(runtime.availableProcessors())
                .activeThreads(Thread.activeCount())
                .timestamp(java.time.LocalDateTime.now())
                .build());
    }
}
