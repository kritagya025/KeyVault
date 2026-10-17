package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyAuditLogExportIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Export User")
                .email("export_audit_user@example.com")
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
                .email("other_audit_user@example.com")
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
    public void testExportKeyAuditLogsAsCsv() throws Exception {
        // 1. Create key
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Audit CSV Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        Long keyId = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class).getId();

        // 2. Update key
        UpdateApiKeyRequest updateReq = UpdateApiKeyRequest.builder()
                .name("Audit CSV Key Renamed")
                .build();

        mockMvc.perform(patch("/api/keys/" + keyId)
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk());

        // 3. Revoke key
        mockMvc.perform(patch("/api/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        // 4. Export audit logs for this key
        MvcResult exportResult = mockMvc.perform(get("/api/keys/" + keyId + "/audit-logs/export")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"api-key-" + keyId + "-audit-logs.csv\""))
                .andReturn();

        String csvContent = exportResult.getResponse().getContentAsString();
        assertThat(csvContent).startsWith("Timestamp,Log ID,API Key ID,Key Name,Action,Details");
        assertThat(csvContent).contains("CREATED");
        assertThat(csvContent).contains("UPDATED");
        assertThat(csvContent).contains("REVOKED");
        assertThat(csvContent).contains("Audit CSV Key");
    }

    @Test
    public void testExportUserAuditLogsAsCsv() throws Exception {
        // Create 2 keys
        for (int i = 1; i <= 2; i++) {
            CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                    .name("User Audit Key " + i)
                    .permissions(Set.of(Permission.READ))
                    .build();

            mockMvc.perform(post("/api/keys")
                            .header("Authorization", "Bearer " + userToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(createReq)))
                    .andExpect(status().isCreated());
        }

        MvcResult exportResult = mockMvc.perform(get("/api/keys/audit-logs/export")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"user-audit-logs.csv\""))
                .andReturn();

        String csvContent = exportResult.getResponse().getContentAsString();
        assertThat(csvContent).startsWith("Timestamp,Log ID,API Key ID,Key Name,Action,Details");
        assertThat(csvContent).contains("User Audit Key 1");
        assertThat(csvContent).contains("User Audit Key 2");
    }

    @Test
    public void testCrossUserAuditLogExportForbidden() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Private Audit Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        Long keyId = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class).getId();

        // Other user attempts to export key audit logs
        mockMvc.perform(get("/api/keys/" + keyId + "/audit-logs/export")
                        .header("Authorization", "Bearer " + otherUserToken))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUnauthenticatedAuditLogExportUnauthorized() throws Exception {
        mockMvc.perform(get("/api/keys/audit-logs/export"))
                .andExpect(status().isUnauthorized());
    }
}
