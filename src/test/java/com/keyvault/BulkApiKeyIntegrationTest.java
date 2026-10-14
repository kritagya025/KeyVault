package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.BulkKeyActionRequest;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class BulkApiKeyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Bulk Key User")
                .email("bulk_user@example.com")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated())
                .andReturn();

        jwtToken = objectMapper.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private Long createKey(String name) throws Exception {
        CreateApiKeyRequest req = CreateApiKeyRequest.builder()
                .name(name)
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult result = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse resp = objectMapper.readValue(result.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        return resp.getId();
    }

    @Test
    public void testBulkRevokeApiKeys() throws Exception {
        Long key1 = createKey("Key One");
        Long key2 = createKey("Key Two");

        BulkKeyActionRequest bulkReq = BulkKeyActionRequest.builder()
                .keyIds(Set.of(key1, key2, 999999L))
                .build();

        mockMvc.perform(post("/api/keys/bulk-revoke")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bulkReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestedCount").value(3))
                .andExpect(jsonPath("$.processedCount").value(2))
                .andExpect(jsonPath("$.successfulIds").isArray())
                .andExpect(jsonPath("$.failedIds[0]").value(999999L));

        mockMvc.perform(get("/api/keys/" + key1)
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));
    }

    @Test
    public void testBulkDeleteApiKeys() throws Exception {
        Long key1 = createKey("Delete One");
        Long key2 = createKey("Delete Two");

        BulkKeyActionRequest bulkReq = BulkKeyActionRequest.builder()
                .keyIds(Set.of(key1, key2))
                .build();

        mockMvc.perform(post("/api/keys/bulk-delete")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bulkReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.processedCount").value(2));

        mockMvc.perform(get("/api/keys/" + key1)
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isNotFound());
    }
}
