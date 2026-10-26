package com.keyvault.controller;

import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.ApiUsageStatsResponse;
import com.keyvault.dto.ApiUsageSummaryResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.UserRepository;
import com.keyvault.service.ApiKeyService;
import com.keyvault.service.ApiUsageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/keys")
@RequiredArgsConstructor
@Tag(name = "3. API Key Management & Usage", description = "API key generation, lifecycle management, and usage statistics")
@SecurityRequirement(name = "BearerAuth")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final ApiUsageService apiUsageService;
    private final UserRepository userRepository;
    private final com.keyvault.service.AuditLogService auditLogService;

    @PostMapping
    @Operation(summary = "Generate API Key", description = "Generate a new API key with optional expiration date and specified permissions (READ, WRITE). Returns the raw API key ONCE.")
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
            Authentication authentication,
            @Valid @RequestBody CreateApiKeyRequest request
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "List User API Keys", description = "Retrieve metadata and permissions for all API keys owned by the authenticated user, with optional status, query, environment, and tag filtering.")
    public ResponseEntity<List<ApiKeyResponse>> getUserApiKeys(
            Authentication authentication,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String status,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String query,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String environment,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String tag
    ) {
        User user = getUser(authentication);
        List<ApiKeyResponse> response = apiKeyService.getUserApiKeys(user, status, query, environment, tag);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/export", produces = "text/csv")
    @Operation(summary = "Export API Keys Catalog as CSV", description = "Download a CSV catalog of API keys owned by the user, with optional status, query, environment, and tag filtering.")
    public ResponseEntity<byte[]> exportApiKeysCsv(
            Authentication authentication,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String status,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String query,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String environment,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String tag
    ) {
        User user = getUser(authentication);
        byte[] csvBytes = apiKeyService.exportUserApiKeysAsCsv(user, status, query, environment, tag);

        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"api-keys-catalog.csv\"")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .body(csvBytes);
    }

    @GetMapping("/summary")
    @Operation(summary = "Get Account API Keys and Usage Summary", description = "Retrieve high-level overview metrics for the authenticated user, including key counts by status and overall API usage counts.")
    public ResponseEntity<com.keyvault.dto.ApiKeyOverviewResponse> getAccountSummary(Authentication authentication) {
        User user = getUser(authentication);
        com.keyvault.dto.ApiKeyOverviewResponse response = apiKeyService.getAccountSummary(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get API Key Details", description = "Retrieve metadata, permissions, and derived status for a specific API key.")
    public ResponseEntity<ApiKeyResponse> getApiKeyById(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.getApiKeyById(user, id);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{id}")
    @Operation(summary = "Update API Key", description = "Update the name or permissions of an active or expired API key. Revoked keys cannot be updated.")
    public ResponseEntity<ApiKeyResponse> updateApiKey(
            Authentication authentication,
            @PathVariable Long id,
            @Valid @RequestBody com.keyvault.dto.UpdateApiKeyRequest request
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.updateApiKey(user, id, request);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{id}/revoke")
    @Operation(summary = "Revoke API Key", description = "Revoke an API key immediately. Revoked keys cannot be regenerated or used for authentication.")
    public ResponseEntity<ApiKeyResponse> revokeApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.revokeApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @org.springframework.web.bind.annotation.DeleteMapping("/{id}")
    @Operation(summary = "Delete API Key", description = "Permanently delete an API key and remove associated usage history.")
    public ResponseEntity<Void> deleteApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        apiKeyService.deleteApiKey(user, id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/bulk-revoke")
    @Operation(summary = "Bulk Revoke API Keys", description = "Revoke multiple API keys in a single operation. Ignores keys that are already revoked.")
    public ResponseEntity<com.keyvault.dto.BulkKeyActionResponse> bulkRevokeApiKeys(
            Authentication authentication,
            @jakarta.validation.Valid @RequestBody com.keyvault.dto.BulkKeyActionRequest request
    ) {
        User user = getUser(authentication);
        com.keyvault.dto.BulkKeyActionResponse response = apiKeyService.bulkRevokeApiKeys(user, request.getKeyIds());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/bulk-delete")
    @Operation(summary = "Bulk Delete API Keys", description = "Permanently delete multiple API keys and their associated usage records in a single operation.")
    public ResponseEntity<com.keyvault.dto.BulkKeyActionResponse> bulkDeleteApiKeys(
            Authentication authentication,
            @jakarta.validation.Valid @RequestBody com.keyvault.dto.BulkKeyActionRequest request
    ) {
        User user = getUser(authentication);
        com.keyvault.dto.BulkKeyActionResponse response = apiKeyService.bulkDeleteApiKeys(user, request.getKeyIds());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/regenerate")
    @Operation(summary = "Regenerate API Key", description = "Regenerate an ACTIVE or EXPIRED API key. Replaces old hash with a new key and returns the raw key ONCE.")
    public ResponseEntity<CreateApiKeyResponse> regenerateApiKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(user, id);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/rotate")
    @Operation(summary = "Rotate API Key with Grace Period", description = "Issue a replacement API key with identical metadata while keeping the existing key active for a grace period (default 24 hours).")
    public ResponseEntity<CreateApiKeyResponse> rotateApiKey(
            Authentication authentication,
            @PathVariable Long id,
            @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody(required = false) com.keyvault.dto.RotateApiKeyRequest request
    ) {
        User user = getUser(authentication);
        CreateApiKeyResponse response = apiKeyService.rotateApiKey(user, id, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/{id}/renew")
    @Operation(summary = "Renew API Key Expiration", description = "Extend the expiration of an active or expired API key by a specified number of days (default 30) or until an explicit date. Revoked keys cannot be renewed.")
    public ResponseEntity<ApiKeyResponse> renewApiKey(
            Authentication authentication,
            @PathVariable Long id,
            @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody(required = false) com.keyvault.dto.RenewApiKeyRequest request
    ) {
        User user = getUser(authentication);
        ApiKeyResponse response = apiKeyService.renewApiKey(user, id, request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage")
    @Operation(summary = "Get API Key Usage Statistics", description = "Retrieve aggregate request statistics (total, successful, failed) for an API key owned by the user.")
    public ResponseEntity<ApiUsageStatsResponse> getUsageStats(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        ApiUsageStatsResponse response = apiUsageService.getUsageStats(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage/recent")
    @Operation(summary = "Get Recent API Key Usage Logs", description = "Retrieve up to 10 recent usage records (endpoint, method, status code, timestamp) for an API key owned by the user.")
    public ResponseEntity<List<ApiUsageSummaryResponse>> getRecentUsage(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        List<ApiUsageSummaryResponse> response = apiUsageService.getRecentUsage(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}/usage/logs")
    @Operation(summary = "Get Paginated API Key Usage Logs", description = "Query paginated usage logs for an API key, with optional filtering by success status, HTTP method, endpoint, and date range.")
    public ResponseEntity<org.springframework.data.domain.Page<ApiUsageSummaryResponse>> getPaginatedUsage(
            Authentication authentication,
            @PathVariable Long id,
            @org.springframework.web.bind.annotation.RequestParam(required = false) Boolean successful,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String httpMethod,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String endpoint,
            @org.springframework.web.bind.annotation.RequestParam(required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME)
            java.time.LocalDateTime startDate,
            @org.springframework.web.bind.annotation.RequestParam(required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME)
            java.time.LocalDateTime endDate,
            @org.springdoc.core.annotations.ParameterObject
            @org.springframework.data.web.PageableDefault(size = 20, sort = "timestamp", direction = org.springframework.data.domain.Sort.Direction.DESC)
            org.springframework.data.domain.Pageable pageable
    ) {
        User user = getUser(authentication);
        org.springframework.data.domain.Page<ApiUsageSummaryResponse> page =
                apiUsageService.getPaginatedUsage(user, id, successful, httpMethod, endpoint, startDate, endDate, pageable);
        return ResponseEntity.ok(page);
    }

    @org.springframework.web.bind.annotation.DeleteMapping("/{id}/usage/logs")
    @Operation(summary = "Clear API Key Usage Logs", description = "Purge usage records for an API key, with optional beforeDate timestamp to only clear older logs.")
    public ResponseEntity<java.util.Map<String, Object>> clearUsageLogs(
            Authentication authentication,
            @PathVariable Long id,
            @org.springframework.web.bind.annotation.RequestParam(required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME)
            java.time.LocalDateTime beforeDate
    ) {
        User user = getUser(authentication);
        int deletedCount = apiUsageService.clearUsageLogs(user, id, beforeDate);
        auditLogService.recordEvent(id, null, user.getId(), "USAGE_CLEARED", "Cleared " + deletedCount + " usage records" + (beforeDate != null ? " older than " + beforeDate : ""));
        return ResponseEntity.ok(java.util.Map.of(
                "apiKeyId", id,
                "deletedCount", deletedCount,
                "message", "Successfully purged " + deletedCount + " usage logs"
        ));
    }

    @GetMapping(value = "/{id}/usage/export", produces = "text/csv")
    @Operation(summary = "Export API Key Usage Logs as CSV", description = "Download full usage history for an API key as a formatted CSV file.")
    public ResponseEntity<byte[]> exportUsageCsv(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        byte[] csvBytes = apiUsageService.exportUsageLogsAsCsv(user, id);

        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"api-key-" + id + "-usage.csv\"")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .body(csvBytes);
    }

    @GetMapping("/usage/stats")
    @Operation(summary = "Get Account API Usage Statistics", description = "Retrieve aggregate request statistics (total, successful, failed, and endpoint breakdown) across all API keys owned by the user.")
    public ResponseEntity<ApiUsageStatsResponse> getAccountUsageStats(Authentication authentication) {
        User user = getUser(authentication);
        ApiUsageStatsResponse response = apiUsageService.getAccountUsageStats(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/usage/recent")
    @Operation(summary = "Get Recent Account API Usage Logs", description = "Retrieve up to 10 recent usage records across all API keys owned by the user.")
    public ResponseEntity<List<ApiUsageSummaryResponse>> getAccountRecentUsage(Authentication authentication) {
        User user = getUser(authentication);
        List<ApiUsageSummaryResponse> response = apiUsageService.getAccountRecentUsage(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/usage/logs")
    @Operation(summary = "Get Paginated Account API Usage Logs", description = "Query paginated usage logs across all API keys owned by the user, with optional filtering by key ID, success status, HTTP method, endpoint, and date range.")
    public ResponseEntity<org.springframework.data.domain.Page<ApiUsageSummaryResponse>> getAccountPaginatedUsage(
            Authentication authentication,
            @org.springframework.web.bind.annotation.RequestParam(required = false) Long apiKeyId,
            @org.springframework.web.bind.annotation.RequestParam(required = false) Boolean successful,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String httpMethod,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String endpoint,
            @org.springframework.web.bind.annotation.RequestParam(required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME)
            java.time.LocalDateTime startDate,
            @org.springframework.web.bind.annotation.RequestParam(required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME)
            java.time.LocalDateTime endDate,
            @org.springdoc.core.annotations.ParameterObject
            @org.springframework.data.web.PageableDefault(size = 20, sort = "timestamp", direction = org.springframework.data.domain.Sort.Direction.DESC)
            org.springframework.data.domain.Pageable pageable
    ) {
        User user = getUser(authentication);
        org.springframework.data.domain.Page<ApiUsageSummaryResponse> page =
                apiUsageService.getAccountPaginatedUsage(user, apiKeyId, successful, httpMethod, endpoint, startDate, endDate, pageable);
        return ResponseEntity.ok(page);
    }

    @GetMapping(value = "/usage/export", produces = "text/csv")
    @Operation(summary = "Export Account API Usage Logs as CSV", description = "Download full usage history across all API keys owned by the user as a formatted CSV file.")
    public ResponseEntity<byte[]> exportAccountUsageCsv(Authentication authentication) {
        User user = getUser(authentication);
        byte[] csvBytes = apiUsageService.exportAccountUsageLogsAsCsv(user);

        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"user-usage-logs.csv\"")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .body(csvBytes);
    }

    @GetMapping("/{id}/audit-logs")
    @Operation(summary = "Get API Key Audit Logs", description = "Retrieve immutable lifecycle audit events for a specific API key.")
    public ResponseEntity<List<com.keyvault.dto.ApiKeyAuditLogResponse>> getAuditLogsForKey(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        List<com.keyvault.dto.ApiKeyAuditLogResponse> response = auditLogService.getAuditLogsForKey(user, id);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/audit-logs")
    @Operation(summary = "Get User Audit Logs", description = "Query paginated audit logs for all API key actions performed by the authenticated user.")
    public ResponseEntity<org.springframework.data.domain.Page<com.keyvault.dto.ApiKeyAuditLogResponse>> getUserAuditLogs(
            Authentication authentication,
            @org.springdoc.core.annotations.ParameterObject
            @org.springframework.data.web.PageableDefault(size = 20, sort = "timestamp", direction = org.springframework.data.domain.Sort.Direction.DESC)
            org.springframework.data.domain.Pageable pageable
    ) {
        User user = getUser(authentication);
        org.springframework.data.domain.Page<com.keyvault.dto.ApiKeyAuditLogResponse> page =
                auditLogService.getAuditLogsForUser(user, pageable);
        return ResponseEntity.ok(page);
    }

    @GetMapping(value = "/{id}/audit-logs/export", produces = "text/csv")
    @Operation(summary = "Export API Key Audit Logs as CSV", description = "Download immutable audit logs for a specific API key as a formatted CSV file.")
    public ResponseEntity<byte[]> exportKeyAuditLogsCsv(
            Authentication authentication,
            @PathVariable Long id
    ) {
        User user = getUser(authentication);
        byte[] csvBytes = auditLogService.exportAuditLogsForKeyAsCsv(user, id);

        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"api-key-" + id + "-audit-logs.csv\"")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .body(csvBytes);
    }

    @GetMapping(value = "/audit-logs/export", produces = "text/csv")
    @Operation(summary = "Export User Audit Logs as CSV", description = "Download all immutable audit logs for the authenticated user's account as a formatted CSV file.")
    public ResponseEntity<byte[]> exportUserAuditLogsCsv(Authentication authentication) {
        User user = getUser(authentication);
        byte[] csvBytes = auditLogService.exportUserAuditLogsAsCsv(user);

        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"user-audit-logs.csv\"")
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .body(csvBytes);
    }

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }
}
