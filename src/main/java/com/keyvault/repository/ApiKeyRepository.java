package com.keyvault.repository;

import com.keyvault.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {

    List<ApiKey> findByUserId(Long userId);

    @Query("SELECT DISTINCT a FROM ApiKey a JOIN FETCH a.user LEFT JOIN FETCH a.permissions WHERE a.keyHash = :keyHash")
    Optional<ApiKey> findByKeyHash(@Param("keyHash") String keyHash);

    @Modifying
    @Query("UPDATE ApiKey a SET a.lastUsedAt = :lastUsedAt WHERE a.id = :id")
    void updateLastUsedAt(@Param("id") Long id, @Param("lastUsedAt") LocalDateTime lastUsedAt);
}
