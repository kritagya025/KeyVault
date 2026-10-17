package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.CreateApiKeyRequest;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyCatalogExportIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Catalog User")
                .email("catalog_user@example.com")
                .password("password123")
                .build();

        MvcResult userResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        userToken = objectMapper.readTree(userResult.getResponse().getContentAsString()).get("accessToken").asText();

        RegisterRequest otherReq = RegisterRequest.builder()
                .name("Other Catalog User")
                .email("other_catalog_user@example.com")
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
    public void testExportApiKeysCatalogAsCsv() throws Exception {
        CreateApiKeyRequest key1 = CreateApiKeyRequest.builder()
                .name("Production Service Key")
                .description("Production analytics ingest service")
                .tags(Set.of("analytics", "prod"))
                .environment(KeyEnvironment.PRODUCTION)
                .permissions(Set.of(Permission.READ, Permission.WRITE))
                .rateLimit(120)
                .build();

        CreateApiKeyRequest key2 = CreateApiKeyRequest.builder()
                .name("Staging Worker Key")
                .description("Worker background tasks")
                .tags(Set.of("worker", "staging"))
                .environment(KeyEnvironment.STAGING)
                .permissions(Set.of(Permission.READ))
                .rateLimit(60)
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(key1)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(key2)))
                .andExpect(status().isCreated());

        MvcResult exportResult = mockMvc.perform(get("/api/keys/export")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"api-keys-catalog.csv\""))
                .andReturn();

        String csv = exportResult.getResponse().getContentAsString();
        assertThat(csv).startsWith("Key ID,Name,Description,Masked Key,Environment,Permissions,Tags,Rate Limit,Status,Created At,Expires At,Last Used At");
        assertThat(csv).contains("Production Service Key");
        assertThat(csv).contains("Production analytics ingest service");
        assertThat(csv).contains("PRODUCTION");
        assertThat(csv).contains("READ;WRITE");
        assertThat(csv).contains("120");
        assertThat(csv).contains("ACTIVE");
        assertThat(csv).contains("Staging Worker Key");
        assertThat(csv).contains("STAGING");
    }

    @Test
    public void testExportApiKeysCatalogWithFilters() throws Exception {
        CreateApiKeyRequest key1 = CreateApiKeyRequest.builder()
                .name("Prod Key")
                .tags(Set.of("prod"))
                .environment(KeyEnvironment.PRODUCTION)
                .permissions(Set.of(Permission.READ))
                .build();

        CreateApiKeyRequest key2 = CreateApiKeyRequest.builder()
                .name("Dev Key")
                .tags(Set.of("dev"))
                .environment(KeyEnvironment.DEVELOPMENT)
                .permissions(Set.of(Permission.READ))
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(key1)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(key2)))
                .andExpect(status().isCreated());

        // Filter by environment=PRODUCTION
        MvcResult filterResult = mockMvc.perform(get("/api/keys/export")
                        .header("Authorization", "Bearer " + userToken)
                        .param("environment", "PRODUCTION"))
                .andExpect(status().isOk())
                .andReturn();

        String csv = filterResult.getResponse().getContentAsString();
        assertThat(csv).contains("Prod Key");
        assertThat(csv).doesNotContain("Dev Key");

        // Filter by tag=dev
        MvcResult tagResult = mockMvc.perform(get("/api/keys/export")
                        .header("Authorization", "Bearer " + userToken)
                        .param("tag", "dev"))
                .andExpect(status().isOk())
                .andReturn();

        String tagCsv = tagResult.getResponse().getContentAsString();
        assertThat(tagCsv).contains("Dev Key");
        assertThat(tagCsv).doesNotContain("Prod Key");
    }

    @Test
    public void testDataIsolationBetweenUsers() throws Exception {
        CreateApiKeyRequest userKey = CreateApiKeyRequest.builder()
                .name("Secret User Key")
                .permissions(Set.of(Permission.READ))
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userKey)))
                .andExpect(status().isCreated());

        // Other user exports keys -> must not see "Secret User Key"
        MvcResult otherExport = mockMvc.perform(get("/api/keys/export")
                        .header("Authorization", "Bearer " + otherUserToken))
                .andExpect(status().isOk())
                .andReturn();

        String otherCsv = otherExport.getResponse().getContentAsString();
        assertThat(otherCsv).doesNotContain("Secret User Key");
    }

    @Test
    public void testUnauthenticatedCatalogExportUnauthorized() throws Exception {
        mockMvc.perform(get("/api/keys/export"))
                .andExpect(status().isUnauthorized());
    }
}
