package com.keyvault.repository;

import com.keyvault.entity.ApiUsage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ApiUsageRepository extends JpaRepository<ApiUsage, Long> {

    long countByApiKeyId(Long apiKeyId);

    long countByApiKeyIdAndSuccessfulTrue(Long apiKeyId);

    long countByApiKeyIdAndSuccessfulFalse(Long apiKeyId);

    List<ApiUsage> findTop10ByApiKeyIdOrderByTimestampDesc(Long apiKeyId);
}
