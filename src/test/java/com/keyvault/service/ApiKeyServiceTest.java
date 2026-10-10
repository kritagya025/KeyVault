package com.keyvault.service;

import com.keyvault.config.ApiKeyGenerator;
import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.Permission;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.ApiKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ApiKeyService}. The repository is mocked; the key generator is real,
 * so hashing behaviour is exercised rather than stubbed.
 */
@ExtendWith(MockitoExtension.class)
class ApiKeyServiceTest {

    private static final Long OWNER_ID = 1L;
    private static final Long INTRUDER_ID = 2L;

    @Mock
    private ApiKeyRepository apiKeyRepository;

    @Mock
    private com.keyvault.repository.ApiUsageRepository apiUsageRepository;

    private ApiKeyGenerator apiKeyGenerator;
    private ApiKeyService apiKeyService;
    private User owner;

    @BeforeEach
    void setUp() {
        apiKeyGenerator = new ApiKeyGenerator();
        apiKeyService = new ApiKeyService(apiKeyRepository, apiKeyGenerator, apiUsageRepository);
        owner = User.builder().id(OWNER_ID).email("owner@example.com").name("Owner").role("ROLE_USER").build();
    }

    private void stubSaveEchoingArgument() {
        when(apiKeyRepository.save(any(ApiKey.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    private ApiKey storedKey(Long id, User user, LocalDateTime createdAt, LocalDateTime expiresAt, boolean revoked) {
        return ApiKey.builder()
                .id(id)
                .name("Stored Key")
                .keyHash(apiKeyGenerator.hashApiKey("kv_live_stored"))
                .user(user)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .revoked(revoked)
                .permissions(Set.of(Permission.READ))
                .build();
    }

    /** Days from now until the given moment, used to assert re-anchored expiry windows. */
    private static long daysFromNowUntil(LocalDateTime moment) {
        return Duration.between(LocalDateTime.now(), moment).toDays();
    }

    @Test
    @DisplayName("Creation persists only the hash and returns the raw key once")
    void createApiKeyPersistsHashNotRawKey() {
        stubSaveEchoingArgument();

        CreateApiKeyResponse response = apiKeyService.createApiKey(owner,
                CreateApiKeyRequest.builder().name("CI Key").permissions(Set.of(Permission.WRITE)).build());

        ArgumentCaptor<ApiKey> captor = ArgumentCaptor.forClass(ApiKey.class);
        verify(apiKeyRepository).save(captor.capture());
        ApiKey persisted = captor.getValue();

        assertTrue(response.getApiKey().startsWith("kv_live_"));
        assertNotEquals(response.getApiKey(), persisted.getKeyHash());
        assertEquals(apiKeyGenerator.hashApiKey(response.getApiKey()), persisted.getKeyHash());
        assertEquals(response.getMaskedKey(), persisted.getMaskedKey());
        assertTrue(response.getMaskedKey().startsWith("kv_live_••••••••"));
        assertEquals(Set.of(Permission.WRITE), persisted.getPermissions());
    }

    @Test
    @DisplayName("Creation without explicit permissions falls back to READ")
    void createApiKeyDefaultsToReadPermission() {
        stubSaveEchoingArgument();

        CreateApiKeyResponse response = apiKeyService.createApiKey(owner,
                CreateApiKeyRequest.builder().name("Defaulted Key").build());

        assertEquals(Set.of(Permission.READ), response.getPermissions());
    }

    @Test
    @DisplayName("Creation rejects an expiry that is already in the past")
    void createApiKeyRejectsPastExpiry() {
        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("Stale Key")
                .expiresAt(LocalDateTime.now().minusMinutes(1))
                .build();

        assertThrows(IllegalArgumentException.class, () -> apiKeyService.createApiKey(owner, request));
        verify(apiKeyRepository, never()).save(any(ApiKey.class));
    }

    @Test
    @DisplayName("A key belonging to someone else is reported as not found rather than forbidden")
    void getApiKeyByIdHidesKeysOwnedByOthers() {
        User intruder = User.builder().id(INTRUDER_ID).email("intruder@example.com").build();
        when(apiKeyRepository.findById(10L))
                .thenReturn(Optional.of(storedKey(10L, owner, LocalDateTime.now(), null, false)));

        assertThrows(ResourceNotFoundException.class, () -> apiKeyService.getApiKeyById(intruder, 10L));
    }

    @Test
    @DisplayName("Revoking an already revoked key does not write again")
    void revokeApiKeyIsIdempotent() {
        when(apiKeyRepository.findById(11L))
                .thenReturn(Optional.of(storedKey(11L, owner, LocalDateTime.now(), null, true)));

        ApiKeyResponse response = apiKeyService.revokeApiKey(owner, 11L);

        assertEquals("REVOKED", response.getStatus());
        verify(apiKeyRepository, never()).save(any(ApiKey.class));
    }

    @Test
    @DisplayName("A revoked key cannot be regenerated")
    void regenerateRejectsRevokedKey() {
        when(apiKeyRepository.findById(12L))
                .thenReturn(Optional.of(storedKey(12L, owner, LocalDateTime.now(), null, true)));

        assertThrows(IllegalStateException.class, () -> apiKeyService.regenerateApiKey(owner, 12L));
    }

    @Test
    @DisplayName("Regenerating an expired key re-anchors its original validity window from now")
    void regenerateExpiredKeyReAnchorsOriginalWindow() {
        ApiKey expired = storedKey(13L, owner,
                LocalDateTime.now().minusDays(31), LocalDateTime.now().minusDays(1), false);
        when(apiKeyRepository.findById(13L)).thenReturn(Optional.of(expired));
        stubSaveEchoingArgument();

        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(owner, 13L);

        assertTrue(response.getExpiresAt().isAfter(LocalDateTime.now()),
                "A regenerated key must not be born expired");
        // The original window was 30 days, so roughly 30 days should remain.
        long remainingDays = daysFromNowUntil(response.getExpiresAt());
        assertTrue(remainingDays >= 29 && remainingDays <= 30,
                "Expected about 30 remaining days but got " + remainingDays);
        assertEquals("ACTIVE", ApiKeyResponse.calculateStatus(expired));
    }

    @Test
    @DisplayName("Regenerating a key whose stored window is unusable grants the fallback lifetime")
    void regenerateExpiredKeyWithoutCreatedAtUsesFallbackLifetime() {
        ApiKey expired = storedKey(14L, owner, null, LocalDateTime.now().minusDays(1), false);
        when(apiKeyRepository.findById(14L)).thenReturn(Optional.of(expired));
        stubSaveEchoingArgument();

        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(owner, 14L);

        long remainingDays = daysFromNowUntil(response.getExpiresAt());
        assertTrue(remainingDays >= 29 && remainingDays <= 30,
                "Expected the 30 day fallback window but got " + remainingDays);
    }

    @Test
    @DisplayName("Regenerating an unexpired key leaves its expiry untouched but rotates the hash")
    void regenerateActiveKeyKeepsExpiry() {
        String originalHash = apiKeyGenerator.hashApiKey("kv_live_stored");
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(5);
        ApiKey active = storedKey(15L, owner, LocalDateTime.now().minusDays(1), expiresAt, false);
        when(apiKeyRepository.findById(15L)).thenReturn(Optional.of(active));
        stubSaveEchoingArgument();

        CreateApiKeyResponse response = apiKeyService.regenerateApiKey(owner, 15L);

        assertEquals(expiresAt, response.getExpiresAt());
        assertNotEquals(originalHash, active.getKeyHash());
        assertEquals(apiKeyGenerator.hashApiKey(response.getApiKey()), active.getKeyHash());
    }

    @Test
    @DisplayName("Updating key modifies its name and permissions")
    void updateApiKeyUpdatesNameAndPermissions() {
        ApiKey key = storedKey(16L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(16L)).thenReturn(Optional.of(key));
        stubSaveEchoingArgument();

        ApiKeyResponse response = apiKeyService.updateApiKey(owner, 16L,
                com.keyvault.dto.UpdateApiKeyRequest.builder()
                        .name("Renamed Key")
                        .permissions(Set.of(Permission.READ, Permission.WRITE))
                        .build());

        assertEquals("Renamed Key", response.getName());
        assertEquals(Set.of(Permission.READ, Permission.WRITE), response.getPermissions());
    }

    @Test
    @DisplayName("Updating a revoked key is rejected")
    void updateApiKeyRejectsRevokedKey() {
        ApiKey revoked = storedKey(17L, owner, LocalDateTime.now(), null, true);
        when(apiKeyRepository.findById(17L)).thenReturn(Optional.of(revoked));

        assertThrows(IllegalStateException.class, () -> apiKeyService.updateApiKey(owner, 17L,
                com.keyvault.dto.UpdateApiKeyRequest.builder().name("New Name").build()));
    }

    @Test
    @DisplayName("Updating permissions with an empty set is rejected")
    void updateApiKeyRejectsEmptyPermissions() {
        ApiKey key = storedKey(18L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(18L)).thenReturn(Optional.of(key));

        assertThrows(IllegalArgumentException.class, () -> apiKeyService.updateApiKey(owner, 18L,
                com.keyvault.dto.UpdateApiKeyRequest.builder().permissions(Set.of()).build()));
    }

    @Test
    @DisplayName("Updating API key sets future expiration date")
    void updateApiKeyUpdatesExpirationDate() {
        ApiKey key = storedKey(181L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(181L)).thenReturn(Optional.of(key));
        stubSaveEchoingArgument();

        LocalDateTime futureExpiry = LocalDateTime.now().plusDays(60);
        ApiKeyResponse response = apiKeyService.updateApiKey(owner, 181L,
                com.keyvault.dto.UpdateApiKeyRequest.builder().expiresAt(futureExpiry).build());

        assertEquals(futureExpiry, response.getExpiresAt());
    }

    @Test
    @DisplayName("Updating API key clears expiration date when requested")
    void updateApiKeyClearsExpirationDate() {
        ApiKey key = storedKey(182L, owner, LocalDateTime.now(), LocalDateTime.now().plusDays(30), false);
        when(apiKeyRepository.findById(182L)).thenReturn(Optional.of(key));
        stubSaveEchoingArgument();

        ApiKeyResponse response = apiKeyService.updateApiKey(owner, 182L,
                com.keyvault.dto.UpdateApiKeyRequest.builder().clearExpiration(true).build());

        org.junit.jupiter.api.Assertions.assertNull(response.getExpiresAt());
    }

    @Test
    @DisplayName("Updating API key rejects past expiration date")
    void updateApiKeyRejectsPastExpirationDate() {
        ApiKey key = storedKey(183L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(183L)).thenReturn(Optional.of(key));

        LocalDateTime pastExpiry = LocalDateTime.now().minusMinutes(5);
        assertThrows(IllegalArgumentException.class, () -> apiKeyService.updateApiKey(owner, 183L,
                com.keyvault.dto.UpdateApiKeyRequest.builder().expiresAt(pastExpiry).build()));
    }

    @Test
    @DisplayName("Deleting an API key removes associated usage logs and deletes key entity")
    void deleteApiKeyRemovesKeyAndUsage() {
        ApiKey key = storedKey(19L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(19L)).thenReturn(Optional.of(key));

        apiKeyService.deleteApiKey(owner, 19L);

        verify(apiUsageRepository).deleteByApiKeyId(19L);
        verify(apiKeyRepository).delete(key);
    }

    @Test
    @DisplayName("Deleting another user's key throws ResourceNotFoundException")
    void deleteApiKeyRejectsNonOwner() {
        User intruder = User.builder().id(INTRUDER_ID).email("intruder@example.com").build();
        ApiKey key = storedKey(20L, owner, LocalDateTime.now(), null, false);
        when(apiKeyRepository.findById(20L)).thenReturn(Optional.of(key));

        assertThrows(ResourceNotFoundException.class, () -> apiKeyService.deleteApiKey(intruder, 20L));
        verify(apiKeyRepository, never()).delete(any(ApiKey.class));
    }

    @Test
    @DisplayName("Listing user keys filters accurately by status")
    void getUserApiKeysFiltersByStatus() {
        ApiKey activeKey = storedKey(21L, owner, LocalDateTime.now(), null, false);
        ApiKey revokedKey = storedKey(22L, owner, LocalDateTime.now(), null, true);
        ApiKey expiredKey = storedKey(23L, owner, LocalDateTime.now().minusDays(10), LocalDateTime.now().minusDays(1), false);

        when(apiKeyRepository.findByUserId(OWNER_ID)).thenReturn(List.of(activeKey, revokedKey, expiredKey));

        List<ApiKeyResponse> activeResults = apiKeyService.getUserApiKeys(owner, "ACTIVE", null);
        assertEquals(1, activeResults.size());
        assertEquals(21L, activeResults.get(0).getId());

        List<ApiKeyResponse> revokedResults = apiKeyService.getUserApiKeys(owner, "revoked", null);
        assertEquals(1, revokedResults.size());
        assertEquals(22L, revokedResults.get(0).getId());

        List<ApiKeyResponse> expiredResults = apiKeyService.getUserApiKeys(owner, "EXPIRED", null);
        assertEquals(1, expiredResults.size());
        assertEquals(23L, expiredResults.get(0).getId());
    }

    @Test
    @DisplayName("Listing user keys filters by name query ignoring case")
    void getUserApiKeysFiltersByQuery() {
        ApiKey key1 = storedKey(24L, owner, LocalDateTime.now(), null, false);
        key1.setName("Production Server Key");
        ApiKey key2 = storedKey(25L, owner, LocalDateTime.now(), null, false);
        key2.setName("Staging Key");

        when(apiKeyRepository.findByUserId(OWNER_ID)).thenReturn(List.of(key1, key2));

        List<ApiKeyResponse> prodResults = apiKeyService.getUserApiKeys(owner, null, "prod");
        assertEquals(1, prodResults.size());
        assertEquals("Production Server Key", prodResults.get(0).getName());

        List<ApiKeyResponse> noResults = apiKeyService.getUserApiKeys(owner, null, "qa");
        assertTrue(noResults.isEmpty());
    }

    @Test
    @DisplayName("Listing user keys throws IllegalArgumentException on invalid status")
    void getUserApiKeysRejectsInvalidStatus() {
        when(apiKeyRepository.findByUserId(OWNER_ID)).thenReturn(List.of());

        assertThrows(IllegalArgumentException.class,
                () -> apiKeyService.getUserApiKeys(owner, "UNKNOWN_STATUS", null));
    }

    @Test
    @DisplayName("Account summary computes aggregate key counts and usage stats")
    void getAccountSummaryComputesCorrectMetrics() {
        ApiKey activeKey = storedKey(31L, owner, LocalDateTime.now(), null, false);
        ApiKey revokedKey = storedKey(32L, owner, LocalDateTime.now(), null, true);
        ApiKey expiredKey = storedKey(33L, owner, LocalDateTime.now().minusDays(10), LocalDateTime.now().minusDays(1), false);

        when(apiKeyRepository.findByUserId(OWNER_ID)).thenReturn(List.of(activeKey, revokedKey, expiredKey));
        when(apiUsageRepository.countByUserId(OWNER_ID)).thenReturn(50L);
        when(apiUsageRepository.countByUserIdAndSuccessfulTrue(OWNER_ID)).thenReturn(45L);
        when(apiUsageRepository.countByUserIdAndSuccessfulFalse(OWNER_ID)).thenReturn(5L);

        com.keyvault.dto.ApiKeyOverviewResponse summary = apiKeyService.getAccountSummary(owner);

        assertEquals(3L, summary.getTotalKeys());
        assertEquals(1L, summary.getActiveKeys());
        assertEquals(1L, summary.getRevokedKeys());
        assertEquals(1L, summary.getExpiredKeys());
        assertEquals(50L, summary.getTotalRequests());
        assertEquals(45L, summary.getSuccessfulRequests());
        assertEquals(5L, summary.getFailedRequests());
    }
}
