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
}
