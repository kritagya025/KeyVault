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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class ApiKeyAuthenticationIntegrationTest {

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
                .name("Auth Consumer")
                .email("auth_consumer@example.com")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated())
                .andReturn();

        String responseStr = result.getResponse().getContentAsString();
        jwtToken = objectMapper.readTree(responseStr).get("accessToken").asText();
    }

    @Test
    public void testValidApiKeyAuthenticationSuccess() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Consumer Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        String rawApiKey = keyResponse.getApiKey();

        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawApiKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, authenticated user!"))
                .andExpect(jsonPath("$.user").value("auth_consumer@example.com"));
    }

    @Test
    public void testInvalidApiKeyAuthenticationFails() throws Exception {
        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", "kv_live_invalid_key_hash_test"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testRevokedApiKeyAuthenticationFails() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Revoke Test Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        String rawApiKey = keyResponse.getApiKey();
        Long keyId = keyResponse.getId();

        mockMvc.perform(patch("/api/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawApiKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testExpiredApiKeyAuthenticationFails() throws Exception {
        User user = userRepository.findByEmail("auth_consumer@example.com").orElseThrow();

        String rawKey = apiKeyGenerator.generateRawApiKey();
        String keyHash = apiKeyGenerator.hashApiKey(rawKey);

        ApiKey expiredKey = ApiKey.builder()
                .name("Expired Key")
                .keyHash(keyHash)
                .user(user)
                .expiresAt(LocalDateTime.now().minusDays(1))
                .permissions(Set.of(Permission.READ))
                .build();

        apiKeyRepository.save(expiredKey);

        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isUnauthorized());
    }
}
