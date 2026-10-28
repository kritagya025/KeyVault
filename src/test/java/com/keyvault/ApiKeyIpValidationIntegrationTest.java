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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ApiKeyIpValidationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userReq = RegisterRequest.builder()
                .name("IP Validation User")
                .email("ip_val_user@example.com")
                .password("password123")
                .build();

        MvcResult userResult = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        userToken = objectMapper.readTree(userResult.getResponse().getContentAsString()).get("accessToken").asText();
    }

    @Test
    public void testCreateKeyWithInvalidIpFails() throws Exception {
        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("Invalid IP Key")
                .permissions(Set.of(Permission.READ))
                .ipRestrictions(Set.of("999.999.999.999"))
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("Invalid IP address or CIDR notation: 999.999.999.999")));
    }

    @Test
    public void testCreateKeyWithInvalidCidrFails() throws Exception {
        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("Invalid CIDR Key")
                .permissions(Set.of(Permission.READ))
                .ipRestrictions(Set.of("192.168.1.0/33"))
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("Invalid IP address or CIDR notation: 192.168.1.0/33")));
    }

    @Test
    public void testUpdateKeyWithInvalidIpFails() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Valid IP Key")
                .permissions(Set.of(Permission.READ))
                .ipRestrictions(Set.of("192.168.1.10"))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);

        UpdateApiKeyRequest updateReq = UpdateApiKeyRequest.builder()
                .ipRestrictions(Set.of("not-an-ip"))
                .build();

        mockMvc.perform(patch("/api/keys/" + keyResponse.getId())
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("Invalid IP address or CIDR notation: not-an-ip")));
    }

    @Test
    public void testCreateAndKeyWithValidIpAndCidrSucceeds() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Valid Multi-IP Key")
                .permissions(Set.of(Permission.READ))
                .ipRestrictions(Set.of("10.0.0.0/8", "192.168.1.1", "::1", "2001:db8::/32"))
                .build();

        mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Valid Multi-IP Key"));
    }
}
