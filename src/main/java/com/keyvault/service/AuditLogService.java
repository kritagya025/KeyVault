package com.keyvault.service;

import com.keyvault.dto.ApiKeyAuditLogResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.ApiKeyAuditLog;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.ApiKeyAuditLogRepository;
import com.keyvault.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final ApiKeyAuditLogRepository auditLogRepository;
    private final ApiKeyRepository apiKeyRepository;

    @Transactional
    public void recordEvent(Long apiKeyId, String keyName, Long userId, String action, String details) {
        ApiKeyAuditLog log = ApiKeyAuditLog.builder()
                .apiKeyId(apiKeyId)
                .keyName(keyName)
                .userId(userId)
                .action(action)
                .details(details)
                .build();
        auditLogRepository.save(log);
    }

    @Transactional(readOnly = true)
    public List<ApiKeyAuditLogResponse> getAuditLogsForKey(User user, Long apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findById(apiKeyId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + apiKeyId));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + apiKeyId);
        }

        return auditLogRepository.findByApiKeyIdOrderByTimestampDesc(apiKeyId)
                .stream()
                .map(ApiKeyAuditLogResponse::fromEntity)
                .toList();
    }

    @Transactional(readOnly = true)
    public Page<ApiKeyAuditLogResponse> getAuditLogsForUser(User user, Pageable pageable) {
        return auditLogRepository.findByUserIdOrderByTimestampDesc(user.getId(), pageable)
                .map(ApiKeyAuditLogResponse::fromEntity);
    }

    @Transactional(readOnly = true)
    public byte[] exportAuditLogsForKeyAsCsv(User user, Long apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findById(apiKeyId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found with id: " + apiKeyId));

        if (!apiKey.getUser().getId().equals(user.getId())) {
            throw new ResourceNotFoundException("API key not found with id: " + apiKeyId);
        }

        List<ApiKeyAuditLog> logs = auditLogRepository.findByApiKeyIdOrderByTimestampDesc(apiKeyId);
        return formatLogsToCsv(logs);
    }

    @Transactional(readOnly = true)
    public byte[] exportUserAuditLogsAsCsv(User user) {
        List<ApiKeyAuditLog> logs = auditLogRepository.findByUserIdOrderByTimestampDesc(user.getId());
        return formatLogsToCsv(logs);
    }

    private byte[] formatLogsToCsv(List<ApiKeyAuditLog> logs) {
        StringBuilder csv = new StringBuilder();
        csv.append("Timestamp,Log ID,API Key ID,Key Name,Action,Details\r\n");

        for (ApiKeyAuditLog log : logs) {
            csv.append(escapeCsv(log.getTimestamp() != null ? log.getTimestamp().toString() : "")).append(",")
               .append(log.getId() != null ? log.getId() : "").append(",")
               .append(log.getApiKeyId() != null ? log.getApiKeyId() : "").append(",")
               .append(escapeCsv(log.getKeyName())).append(",")
               .append(escapeCsv(log.getAction())).append(",")
               .append(escapeCsv(log.getDetails())).append("\r\n");
        }

        return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private String escapeCsv(String val) {
        if (val == null) {
            return "";
        }
        if (val.contains(",") || val.contains("\"") || val.contains("\n") || val.contains("\r")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return val;
    }
}
