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

    private ApiKeyGenerator apiKeyGenerator;
    private ApiKeyService apiKeyService;
    private User owner;

    @BeforeEach
    void setUp() {
        apiKeyGenerator = new ApiKeyGenerator();
        apiKeyService = new ApiKeyService(apiKeyRepository, apiKeyGenerator);
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
}
