package com.keyvault.service;

import com.keyvault.dto.ApiUsageStatsResponse;
import com.keyvault.dto.ApiUsageSummaryResponse;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.ApiUsage;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.ApiKeyRepository;
import com.keyvault.repository.ApiUsageRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ApiUsageService}. */
@ExtendWith(MockitoExtension.class)
class ApiUsageServiceTest {

    private static final Long KEY_ID = 7L;

    @Mock
    private ApiUsageRepository apiUsageRepository;

    @Mock
    private ApiKeyRepository apiKeyRepository;

    @InjectMocks
    private ApiUsageService apiUsageService;

    private User owner;
    private ApiKey ownedKey;

    @BeforeEach
    void setUp() {
        owner = User.builder().id(1L).email("owner@example.com").build();
        ownedKey = ApiKey.builder().id(KEY_ID).name("Owned Key").user(owner).build();
    }

    @Test
    @DisplayName("Recording usage stores the endpoint, method, status and success flag")
    void recordUsagePersistsRequestMetadata() {
        apiUsageService.recordUsage(ownedKey, "/api/protected/write", "POST", 403, false);

        ArgumentCaptor<ApiUsage> captor = ArgumentCaptor.forClass(ApiUsage.class);
        verify(apiUsageRepository).save(captor.capture());
        ApiUsage persisted = captor.getValue();

        assertSame(ownedKey, persisted.getApiKey());
        assertEquals("/api/protected/write", persisted.getEndpoint());
        assertEquals("POST", persisted.getHttpMethod());
        assertEquals(403, persisted.getStatusCode());
        assertFalse(persisted.isSuccessful());
    }

    @Test
    @DisplayName("Stats aggregate total, successful and failed request counts")
    void getUsageStatsAggregatesCounts() {
        when(apiKeyRepository.findById(KEY_ID)).thenReturn(Optional.of(ownedKey));
        when(apiUsageRepository.countByApiKeyId(KEY_ID)).thenReturn(10L);
        when(apiUsageRepository.countByApiKeyIdAndSuccessfulTrue(KEY_ID)).thenReturn(7L);
        when(apiUsageRepository.countByApiKeyIdAndSuccessfulFalse(KEY_ID)).thenReturn(3L);

        ApiUsageStatsResponse stats = apiUsageService.getUsageStats(owner, KEY_ID);

        assertEquals(KEY_ID, stats.getApiKeyId());
        assertEquals(10L, stats.getTotalRequests());
        assertEquals(7L, stats.getSuccessfulRequests());
        assertEquals(3L, stats.getFailedRequests());
    }

    @Test
    @DisplayName("Recent usage maps entities to summaries without exposing the key")
    void getRecentUsageMapsSummaries() {
        when(apiKeyRepository.findById(KEY_ID)).thenReturn(Optional.of(ownedKey));
        LocalDateTime recordedAt = LocalDateTime.now();
        when(apiUsageRepository.findTop10ByApiKeyIdOrderByTimestampDesc(KEY_ID)).thenReturn(List.of(
                ApiUsage.builder().apiKey(ownedKey).endpoint("/api/protected/read")
                        .httpMethod("GET").statusCode(200).successful(true).timestamp(recordedAt).build()));

        List<ApiUsageSummaryResponse> recent = apiUsageService.getRecentUsage(owner, KEY_ID);

        assertEquals(1, recent.size());
        assertEquals("/api/protected/read", recent.get(0).getEndpoint());
        assertEquals("GET", recent.get(0).getMethod());
        assertEquals(200, recent.get(0).getStatusCode());
        assertEquals(recordedAt, recent.get(0).getTimestamp());
    }

    @Test
    @DisplayName("Usage for another user's key is reported as not found")
    void getUsageStatsHidesKeysOwnedByOthers() {
        User intruder = User.builder().id(2L).email("intruder@example.com").build();
        when(apiKeyRepository.findById(KEY_ID)).thenReturn(Optional.of(ownedKey));

        assertThrows(ResourceNotFoundException.class, () -> apiUsageService.getUsageStats(intruder, KEY_ID));
        verify(apiUsageRepository, never()).countByApiKeyId(anyLong());
    }

    @Test
    @DisplayName("Usage for a key that does not exist is reported as not found")
    void getUsageStatsRejectsMissingKey() {
        when(apiKeyRepository.findById(404L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> apiUsageService.getUsageStats(owner, 404L));
    }
}
