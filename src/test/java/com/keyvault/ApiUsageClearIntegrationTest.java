package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.ApiKey;
import com.keyvault.entity.Permission;
import com.keyvault.repository.ApiKeyRepository;
import com.keyvault.service.ApiUsageService;
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
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiUsageClearIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private ApiUsageService apiUsageService;

    private String jwtToken;
    private Long keyId;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Usage Filter User")
                .email("usage_filter_user@example.com")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated())
                .andReturn();

        jwtToken = objectMapper.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();

        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("Usage Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult keyResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResp = objectMapper.readValue(keyResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        keyId = keyResp.getId();

        ApiKey apiKey = apiKeyRepository.findById(keyId).orElseThrow();
        apiUsageService.recordUsage(apiKey, "/api/protected/read", "GET", 200, true);
        apiUsageService.recordUsage(apiKey, "/api/protected/write", "POST", 403, false);
    }

    @Test
    public void testDateRangeFilteringOnUsageLogs() throws Exception {
        LocalDateTime past = LocalDateTime.now().minusHours(2);
        LocalDateTime future = LocalDateTime.now().plusHours(2);

        mockMvc.perform(get("/api/keys/" + keyId + "/usage/logs")
                        .header("Authorization", "Bearer " + jwtToken)
                        .param("startDate", past.toString())
                        .param("endDate", future.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2));

        mockMvc.perform(get("/api/keys/" + keyId + "/usage/logs")
                        .header("Authorization", "Bearer " + jwtToken)
                        .param("startDate", future.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0));
    }

    @Test
    public void testClearUsageLogs() throws Exception {
        mockMvc.perform(delete("/api/keys/" + keyId + "/usage/logs")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deletedCount").value(2));

        mockMvc.perform(get("/api/keys/" + keyId + "/usage/logs")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0));
    }
}
