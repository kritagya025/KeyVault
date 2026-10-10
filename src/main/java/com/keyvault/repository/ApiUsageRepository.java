package com.keyvault.repository;

import com.keyvault.entity.ApiUsage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ApiUsageRepository extends JpaRepository<ApiUsage, Long> {

    long countByApiKeyId(Long apiKeyId);

    long countByApiKeyIdAndSuccessfulTrue(Long apiKeyId);

    long countByApiKeyIdAndSuccessfulFalse(Long apiKeyId);

    @Query("SELECT COUNT(u) FROM ApiUsage u WHERE u.apiKey.user.id = :userId")
    long countByUserId(@Param("userId") Long userId);

    @Query("SELECT COUNT(u) FROM ApiUsage u WHERE u.apiKey.user.id = :userId AND u.successful = true")
    long countByUserIdAndSuccessfulTrue(@Param("userId") Long userId);

    @Query("SELECT COUNT(u) FROM ApiUsage u WHERE u.apiKey.user.id = :userId AND u.successful = false")
    long countByUserIdAndSuccessfulFalse(@Param("userId") Long userId);

    List<ApiUsage> findTop10ByApiKeyIdOrderByTimestampDesc(Long apiKeyId);

    org.springframework.data.domain.Page<ApiUsage> findByApiKeyId(Long apiKeyId, org.springframework.data.domain.Pageable pageable);

    org.springframework.data.domain.Page<ApiUsage> findByApiKeyIdAndSuccessful(Long apiKeyId, boolean successful, org.springframework.data.domain.Pageable pageable);

    @Query("SELECT new com.keyvault.dto.EndpointUsageCount(u.endpoint, COUNT(u)) " +
           "FROM ApiUsage u WHERE u.apiKey.id = :apiKeyId GROUP BY u.endpoint ORDER BY COUNT(u) DESC")
    List<com.keyvault.dto.EndpointUsageCount> countRequestsByEndpoint(@Param("apiKeyId") Long apiKeyId);

    @Modifying
    @Query("DELETE FROM ApiUsage u WHERE u.apiKey.id = :apiKeyId")
    void deleteByApiKeyId(@Param("apiKeyId") Long apiKeyId);
}
