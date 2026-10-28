package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.DuplicateApiKeyRequest;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.KeyEnvironment;
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
public class ApiKeyDuplicationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Duplication User")
                .email("duplication_user@example.com")
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
                .email("other_duplication_user@example.com")
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
    public void testDuplicateApiKeyWithCustomNameAndAuthenticate() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Original Staging Service")
                .description("Staging key with permissions and restrictions")
                .environment(KeyEnvironment.STAGING)
                .rateLimit(60)
                .permissions(Set.of(Permission.READ, Permission.WRITE))
                .tags(Set.of("staging", "api"))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse original = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // Duplicate with custom name
        DuplicateApiKeyRequest dupReq = DuplicateApiKeyRequest.builder()
                .name("Cloned Staging Service")
                .build();

        MvcResult dupResult = mockMvc.perform(post("/api/keys/" + original.getId() + "/duplicate")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dupReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Cloned Staging Service"))
                .andExpect(jsonPath("$.description").value("Staging key with permissions and restrictions"))
                .andExpect(jsonPath("$.environment").value("STAGING"))
                .andExpect(jsonPath("$.rateLimit").value(60))
                .andExpect(jsonPath("$.apiKey").isNotEmpty())
                .andReturn();

        CreateApiKeyResponse duplicate = objectMapper.readValue(dupResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        assertThat(duplicate.getId()).isNotEqualTo(original.getId());
        assertThat(duplicate.getApiKey()).isNotEqualTo(original.getApiKey());
        assertThat(duplicate.getMaskedKey()).isNotEqualTo(original.getMaskedKey());

        // Authenticate with newly issued duplicate key
        mockMvc.perform(get("/api/protected/hello")
                        .header("X-API-Key", duplicate.getApiKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("duplication_user@example.com"));

        // Verify DUPLICATED audit event
        mockMvc.perform(get("/api/keys/" + duplicate.getId() + "/audit-logs")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].action").value("DUPLICATED"))
                .andExpect(jsonPath("$[0].details").value(org.hamcrest.Matchers.containsString("Duplicated configuration from key #" + original.getId())));
    }

    @Test
    public void testDuplicateApiKeyWithDefaultNameFallback() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Root Worker")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse original = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // Duplicate without body -> name defaults to "Copy of Root Worker"
        mockMvc.perform(post("/api/keys/" + original.getId() + "/duplicate")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Copy of Root Worker"))
                .andExpect(jsonPath("$.apiKey").isNotEmpty());
    }

    @Test
    public void testDuplicateApiKeyFailsForRevokedKey() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Key to Revoke")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse original = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // Revoke the key
        mockMvc.perform(patch("/api/keys/" + original.getId() + "/revoke")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        // Attempting to duplicate a revoked key should return 400 Bad Request
        mockMvc.perform(post("/api/keys/" + original.getId() + "/duplicate")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Cannot duplicate a revoked API key"));
    }

    @Test
    public void testDuplicateApiKeyEnforcesOwnership() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("User A Secret Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse original = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // User B attempts to duplicate User A's key -> 404 Not Found
        mockMvc.perform(post("/api/keys/" + original.getId() + "/duplicate")
                        .header("Authorization", "Bearer " + otherUserToken))
                .andExpect(status().isNotFound());
    }
}
