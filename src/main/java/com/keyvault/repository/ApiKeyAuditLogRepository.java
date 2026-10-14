package com.keyvault.repository;

import com.keyvault.entity.ApiKeyAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ApiKeyAuditLogRepository extends JpaRepository<ApiKeyAuditLog, Long> {

    List<ApiKeyAuditLog> findByApiKeyIdOrderByTimestampDesc(Long apiKeyId);

    Page<ApiKeyAuditLog> findByUserIdOrderByTimestampDesc(Long userId, Pageable pageable);

    Page<ApiKeyAuditLog> findByApiKeyIdOrderByTimestampDesc(Long apiKeyId, Pageable pageable);
}
