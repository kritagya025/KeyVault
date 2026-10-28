package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.Permission;
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

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyPauseResumeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Pause User")
                .email("pause_user@example.com")
                .password("password123")
                .build();

        MvcResult userResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        userToken = objectMapper.readTree(userResult.getResponse().getContentAsString()).get("accessToken").asText();

        RegisterRequest otherReq = RegisterRequest.builder()
                .name("Other User")
                .email("other_pause_user@example.com")
                .password("password123")
                .build();

        MvcResult otherResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otherReq)))
                .andExpect(status().isCreated())
                .andReturn();

        otherUserToken = objectMapper.readTree(otherResult.getResponse().getContentAsString()).get("accessToken").asText();
    }

    @Test
    public void testPauseAndResumeLifecycleFlow() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Payment Worker")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        String rawApiKey = keyResponse.getApiKey();
        Long keyId = keyResponse.getId();

        // 1. Valid authentication initially
        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawApiKey))
                .andExpect(status().isOk());

        // 2. Pause the key
        mockMvc.perform(patch("/api/keys/" + keyId + "/pause")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PAUSED"))
                .andExpect(jsonPath("$.paused").value(true));

        // 3. Paused key authentication is rejected
        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawApiKey))
                .andExpect(status().isUnauthorized());

        // 4. Listing with ?status=PAUSED returns the key
        mockMvc.perform(get("/api/keys?status=PAUSED")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(keyId))
                .andExpect(jsonPath("$[0].status").value("PAUSED"));

        // 5. Resume the key
        mockMvc.perform(patch("/api/keys/" + keyId + "/resume")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.paused").value(false));

        // 6. Resumed key authentication succeeds again
        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", rawApiKey))
                .andExpect(status().isOk());

        // 7. Check audit logs
        mockMvc.perform(get("/api/keys/" + keyId + "/audit-logs")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].action").value("RESUMED"))
                .andExpect(jsonPath("$[1].action").value("PAUSED"));
    }

    @Test
    public void testPauseAlreadyPausedKeyThrowsBadRequest() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Double Pause Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        Long keyId = keyResponse.getId();

        mockMvc.perform(patch("/api/keys/" + keyId + "/pause")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        // Attempting to pause again
        mockMvc.perform(patch("/api/keys/" + keyId + "/pause")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("API key is already paused"));
    }

    @Test
    public void testResumeNonPausedKeyThrowsBadRequest() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Already Active Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        Long keyId = keyResponse.getId();

        // Attempting to resume an active key
        mockMvc.perform(patch("/api/keys/" + keyId + "/resume")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("API key is not paused"));
    }

    @Test
    public void testPauseRevokedKeyFails() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Revoked Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        Long keyId = keyResponse.getId();

        mockMvc.perform(patch("/api/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        mockMvc.perform(patch("/api/keys/" + keyId + "/pause")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Cannot pause a revoked API key"));
    }

    @Test
    public void testPauseEnforcesOwnership() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Protected Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        Long keyId = keyResponse.getId();

        // Other user attempts to pause -> 404
        mockMvc.perform(patch("/api/keys/" + keyId + "/pause")
                        .header("Authorization", "Bearer " + otherUserToken))
                .andExpect(status().isNotFound());
    }
}
