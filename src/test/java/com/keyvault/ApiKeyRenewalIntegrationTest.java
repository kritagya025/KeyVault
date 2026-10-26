package com.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyvault.dto.CreateApiKeyRequest;
import com.keyvault.dto.CreateApiKeyResponse;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.dto.RenewApiKeyRequest;
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

import java.time.LocalDateTime;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyRenewalIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String otherUserToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("Renewal User")
                .email("renewal_user@example.com")
                .password("password123")
                .build();

        MvcResult userResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        userToken = objectMapper.readTree(userResult.getResponse().getContentAsString()).get("accessToken").asText();

        RegisterRequest otherReq = RegisterRequest.builder()
                .name("Other Renewal User")
                .email("other_renewal_user@example.com")
                .password("password123")
                .build();

        MvcResult otherResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otherReq)))
                .andExpect(status().isCreated())
                .andReturn();

        otherUserToken = objectMapper.readTree(otherResult.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private CreateApiKeyResponse createKeyWithExpiry(String token, String name, LocalDateTime expiry) throws Exception {
        CreateApiKeyRequest req = CreateApiKeyRequest.builder()
                .name(name)
                .permissions(Set.of(Permission.READ))
                .expiresAt(expiry)
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
    public void testRenewActiveKeyExtendsExpirationAndCreatesAuditLog() throws Exception {
        LocalDateTime initialExpiry = LocalDateTime.now().plusDays(2);
        CreateApiKeyResponse key = createKeyWithExpiry(userToken, "Expiring Soon Key", initialExpiry);

        RenewApiKeyRequest renewReq = RenewApiKeyRequest.builder()
                .extensionDays(60)
                .build();

        MvcResult renewResult = mockMvc.perform(post("/api/keys/" + key.getId() + "/renew")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(renewReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.expiringSoon").value(false))
                .andReturn();

        // Audit log should contain RENEWED event
        mockMvc.perform(get("/api/keys/" + key.getId() + "/audit-logs")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.action == 'RENEWED')]").isNotEmpty());
    }

    @Test
    public void testRenewRevokedKeyFails() throws Exception {
        CreateApiKeyResponse key = createKeyWithExpiry(userToken, "Key To Revoke", LocalDateTime.now().plusDays(10));

        // Revoke key
        mockMvc.perform(patch("/api/keys/" + key.getId() + "/revoke")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        // Attempt renewal on revoked key
        mockMvc.perform(post("/api/keys/" + key.getId() + "/renew")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Cannot renew a revoked API key"));
    }

    @Test
    public void testFilterByExpiringSoon() throws Exception {
        // Key 1: expires in 3 days (expiring soon)
        createKeyWithExpiry(userToken, "Key Expiring In 3 Days", LocalDateTime.now().plusDays(3));

        // Key 2: expires in 40 days (not expiring soon)
        createKeyWithExpiry(userToken, "Key Expiring In 40 Days", LocalDateTime.now().plusDays(40));

        // Query with status=EXPIRING_SOON
        mockMvc.perform(get("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .param("status", "EXPIRING_SOON"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].name").value("Key Expiring In 3 Days"));

        // Export with status=EXPIRING_SOON
        MvcResult exportResult = mockMvc.perform(get("/api/keys/export")
                        .header("Authorization", "Bearer " + userToken)
                        .param("status", "EXPIRING_SOON"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andReturn();

        String csv = exportResult.getResponse().getContentAsString();
        assertThat(csv).contains("Key Expiring In 3 Days");
        assertThat(csv).doesNotContain("Key Expiring In 40 Days");
    }

    @Test
    public void testCrossUserRenewalForbidden() throws Exception {
        CreateApiKeyResponse userKey = createKeyWithExpiry(userToken, "User Key", LocalDateTime.now().plusDays(5));

        // Other user attempts to renew User 1's key
        mockMvc.perform(post("/api/keys/" + userKey.getId() + "/renew")
                        .header("Authorization", "Bearer " + otherUserToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUnauthenticatedRenewalUnauthorized() throws Exception {
        mockMvc.perform(post("/api/keys/1/renew")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }
}
