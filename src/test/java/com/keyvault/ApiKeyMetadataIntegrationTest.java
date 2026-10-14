package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.ApiKeyResponse;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.dto.UpdateApiKeyRequest;
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
public class ApiKeyMetadataIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Metadata User")
                .email("metadata_user@example.com")
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
    public void testCreateAndUpdateKeyWithDescriptionAndTags() throws Exception {
        CreateApiKeyRequest req = CreateApiKeyRequest.builder()
                .name("Analytics Service Key")
                .description("Used by analytics microservice for daily ingestion")
                .tags(Set.of("analytics", "batch", "internal"))
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Analytics Service Key"))
                .andExpect(jsonPath("$.description").value("Used by analytics microservice for daily ingestion"))
                .andExpect(jsonPath("$.tags").isArray())
                .andReturn();

        CreateApiKeyResponse created = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        // Filter keys by tag
        mockMvc.perform(get("/api/keys?tag=analytics")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(created.getId()));

        mockMvc.perform(get("/api/keys?tag=nonexistent")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        // Update description and tags
        UpdateApiKeyRequest updateReq = UpdateApiKeyRequest.builder()
                .description("Updated ingestion service description")
                .tags(Set.of("analytics", "v2"))
                .build();

        mockMvc.perform(patch("/api/keys/" + created.getId())
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.description").value("Updated ingestion service description"));

        // Verify retrieval
        mockMvc.perform(get("/api/keys/" + created.getId())
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.description").value("Updated ingestion service description"));
    }
}
