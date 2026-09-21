package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.config.ApiKeyGenerator;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.Permission;
import com.keyvault.entity.User;
import com.keyvault.repository.ApiKeyRepository;
import com.keyvault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyRegenerationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ApiKeyGenerator apiKeyGenerator;

    private String jwtToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Regeneration User")
                .email("regeneration_user@example.com")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated())
                .andReturn();

        jwtToken = objectMapper.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();
    }

    @Test
    public void testRegeneratedKeyAuthenticatesAndOldKeyStopsWorking() throws Exception {
        CreateApiKeyResponse original = createKey("Rotating Key");

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", original.getApiKey()))
                .andExpect(status().isOk());

        MvcResult regenerateResult = mockMvc.perform(post("/api/keys/" + original.getId() + "/regenerate")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andReturn();

        CreateApiKeyResponse regenerated = objectMapper.readValue(
                regenerateResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        assertNotEquals(original.getApiKey(), regenerated.getApiKey(), "Regeneration must issue a different raw key");

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", regenerated.getApiKey()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", original.getApiKey()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testRegeneratingExpiredKeyYieldsUsableKey() throws Exception {
        User user = userRepository.findByEmail("regeneration_user@example.com").orElseThrow();

        String staleRawKey = apiKeyGenerator.generateRawApiKey();
        ApiKey expiredKey = ApiKey.builder()
                .name("Expired Rotating Key")
                .keyHash(apiKeyGenerator.hashApiKey(staleRawKey))
                .user(user)
                .createdAt(LocalDateTime.now().minusDays(31))
                .expiresAt(LocalDateTime.now().minusDays(1))
                .permissions(EnumSet.of(Permission.READ))
                .build();
        Long expiredKeyId = apiKeyRepository.save(expiredKey).getId();

        mockMvc.perform(get("/api/keys/" + expiredKeyId).header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("EXPIRED"));

        MvcResult regenerateResult = mockMvc.perform(post("/api/keys/" + expiredKeyId + "/regenerate")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andReturn();

        CreateApiKeyResponse regenerated = objectMapper.readValue(
                regenerateResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        assertTrue(regenerated.getExpiresAt().isAfter(LocalDateTime.now()),
                "Regenerating an expired key must move its expiry into the future");

        // The whole point of the fix: the newly issued key is immediately usable.
        mockMvc.perform(get("/api/protected/read").header("X-API-Key", regenerated.getApiKey()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/keys/" + expiredKeyId).header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    public void testRegeneratingRevokedKeyIsRejected() throws Exception {
        CreateApiKeyResponse key = createKey("Doomed Key");

        mockMvc.perform(patch("/api/keys/" + key.getId() + "/revoke")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/keys/" + key.getId() + "/regenerate")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Cannot regenerate a revoked API key"));
    }

    private CreateApiKeyResponse createKey(String name) throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name(name)
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult result = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        return objectMapper.readValue(result.getResponse().getContentAsString(), CreateApiKeyResponse.class);
    }
}
