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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Key Test User")
                .email("key_test_user@example.com")
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
    public void testCreateListGetRevokeRegenerateApiKeyFlow() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Integration Key")
                .permissions(Set.of(Permission.READ, Permission.WRITE))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.apiKey").isNotEmpty())
                .andExpect(jsonPath("$.name").value("Integration Key"))
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        Long keyId = keyResponse.getId();

        mockMvc.perform(get("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(keyId))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"));

        mockMvc.perform(get("/api/keys/" + keyId)
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(keyId))
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        // Test updating name and permissions
        com.keyvault.dto.UpdateApiKeyRequest updateReq = com.keyvault.dto.UpdateApiKeyRequest.builder()
                .name("Updated Name")
                .permissions(Set.of(Permission.READ))
                .build();

        mockMvc.perform(patch("/api/keys/" + keyId)
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated Name"))
                .andExpect(jsonPath("$.permissions[0]").value("READ"))
                .andExpect(jsonPath("$.permissions.length()").value(1));

        mockMvc.perform(patch("/api/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true))
                .andExpect(jsonPath("$.status").value("REVOKED"));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/api/keys/" + keyId)
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/keys/" + keyId)
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testListApiKeysWithStatusAndQueryFiltering() throws Exception {
        CreateApiKeyRequest activeReq = CreateApiKeyRequest.builder()
                .name("Production Service Key")
                .permissions(Set.of(Permission.READ))
                .build();
        CreateApiKeyRequest stagingReq = CreateApiKeyRequest.builder()
                .name("Staging Analytics Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult activeResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(activeReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse activeKey = objectMapper.readValue(activeResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        MvcResult stagingResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(stagingReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse stagingKey = objectMapper.readValue(stagingResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // Revoke the staging key
        mockMvc.perform(patch("/api/keys/" + stagingKey.getId() + "/revoke")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk());

        // Filter by ACTIVE
        mockMvc.perform(get("/api/keys?status=ACTIVE")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(activeKey.getId()));

        // Filter by REVOKED
        mockMvc.perform(get("/api/keys?status=REVOKED")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(stagingKey.getId()));

        // Search by name query "prod"
        mockMvc.perform(get("/api/keys?query=prod")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].name").value("Production Service Key"));

        // Unknown status returns 400 Bad Request
        mockMvc.perform(get("/api/keys?status=INVALID_STATUS")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isNotEmpty());
    }
}
