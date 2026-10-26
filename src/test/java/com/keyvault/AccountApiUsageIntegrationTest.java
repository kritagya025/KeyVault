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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class AccountApiUsageIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Account Usage User")
                .email("account_usage_user@example.com")
                .password("password123")
                .build();

        MvcResult userResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        userToken = objectMapper.readTree(userResult.getResponse().getContentAsString()).get("accessToken").asText();

        RegisterRequest otherReq = RegisterRequest.builder()
                .name("Other Usage User")
                .email("other_usage_user@example.com")
                .password("password123")
                .build();

        MvcResult otherResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otherReq)))
                .andExpect(status().isCreated())
                .andReturn();

        otherUserToken = objectMapper.readTree(otherResult.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private CreateApiKeyResponse createKey(String token, String name, Set<Permission> permissions) throws Exception {
        CreateApiKeyRequest req = CreateApiKeyRequest.builder()
                .name(name)
                .permissions(permissions)
                .build();

        MvcResult result = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();

        return objectMapper.readValue(result.getResponse().getContentAsString(), CreateApiKeyResponse.class);
    }

    @Test
    public void testAccountUsageStatsAcrossMultipleKeys() throws Exception {
        CreateApiKeyResponse key1 = createKey(userToken, "Service Alpha", Set.of(Permission.READ));
        CreateApiKeyResponse key2 = createKey(userToken, "Service Beta", Set.of(Permission.READ, Permission.WRITE));

        // Key 1: 1 read (success), 1 write (forbidden)
        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key1.getApiKey()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/protected/write").header("X-API-Key", key1.getApiKey()))
                .andExpect(status().isForbidden());

        // Key 2: 1 read (success), 1 write (success)
        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key2.getApiKey()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/protected/write").header("X-API-Key", key2.getApiKey()))
                .andExpect(status().isOk());

        // Account stats
        mockMvc.perform(get("/api/keys/usage/stats")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalRequests").value(4))
                .andExpect(jsonPath("$.successfulRequests").value(3))
                .andExpect(jsonPath("$.failedRequests").value(1))
                .andExpect(jsonPath("$.requestsByEndpoint['/api/protected/read']").value(2))
                .andExpect(jsonPath("$.requestsByEndpoint['/api/protected/write']").value(2));
    }

    @Test
    public void testAccountRecentUsageAndKeyNameMapping() throws Exception {
        CreateApiKeyResponse key1 = createKey(userToken, "Key Alpha", Set.of(Permission.READ));
        CreateApiKeyResponse key2 = createKey(userToken, "Key Beta", Set.of(Permission.READ));

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key1.getApiKey()))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key2.getApiKey()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/keys/usage/recent")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].keyName").isNotEmpty())
                .andExpect(jsonPath("$[0].apiKeyId").isNotEmpty());
    }

    @Test
    public void testAccountPaginatedUsageAndFiltering() throws Exception {
        CreateApiKeyResponse key1 = createKey(userToken, "Alpha Key", Set.of(Permission.READ));
        CreateApiKeyResponse key2 = createKey(userToken, "Beta Key", Set.of(Permission.READ, Permission.WRITE));

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key1.getApiKey()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/protected/write").header("X-API-Key", key1.getApiKey()))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/protected/write").header("X-API-Key", key2.getApiKey()))
                .andExpect(status().isOk());

        // Filter by apiKeyId
        mockMvc.perform(get("/api/keys/usage/logs")
                        .header("Authorization", "Bearer " + userToken)
                        .param("apiKeyId", String.valueOf(key1.getId())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page.totalElements").value(2));

        // Filter by successful=false
        mockMvc.perform(get("/api/keys/usage/logs")
                        .header("Authorization", "Bearer " + userToken)
                        .param("successful", "false"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].method").value("POST"))
                .andExpect(jsonPath("$.content[0].statusCode").value(403));

        // Filter by httpMethod=POST
        mockMvc.perform(get("/api/keys/usage/logs")
                        .header("Authorization", "Bearer " + userToken)
                        .param("httpMethod", "POST"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page.totalElements").value(2));
    }

    @Test
    public void testAccountUsageExportCsv() throws Exception {
        CreateApiKeyResponse key = createKey(userToken, "Exportable Key", Set.of(Permission.READ));

        mockMvc.perform(get("/api/protected/read").header("X-API-Key", key.getApiKey()))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(get("/api/keys/usage/export")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"user-usage-logs.csv\""))
                .andReturn();

        String csv = result.getResponse().getContentAsString();
        assertThat(csv).startsWith("Timestamp,Key ID,Key Name,HTTP Method,Endpoint,Status Code,Success");
        assertThat(csv).contains("Exportable Key");
        assertThat(csv).contains("/api/protected/read");
        assertThat(csv).contains("200,true");
    }

    @Test
    public void testCrossUserAccountUsageIsolation() throws Exception {
        CreateApiKeyResponse userKey = createKey(userToken, "User Key", Set.of(Permission.READ));
        mockMvc.perform(get("/api/protected/read").header("X-API-Key", userKey.getApiKey()))
                .andExpect(status().isOk());

        // Other user's account stats should be empty
        mockMvc.perform(get("/api/keys/usage/stats")
                        .header("Authorization", "Bearer " + otherUserToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalRequests").value(0));

        // Other user querying with User 1's apiKeyId should be rejected with 404
        mockMvc.perform(get("/api/keys/usage/logs")
                        .header("Authorization", "Bearer " + otherUserToken)
                        .param("apiKeyId", String.valueOf(userKey.getId())))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUnauthenticatedAccountUsageUnauthorized() throws Exception {
        mockMvc.perform(get("/api/keys/usage/stats"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/keys/usage/recent"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/keys/usage/logs"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/keys/usage/export"))
                .andExpect(status().isUnauthorized());
    }
}
