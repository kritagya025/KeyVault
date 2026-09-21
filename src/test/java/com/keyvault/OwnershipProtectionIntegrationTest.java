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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class OwnershipProtectionIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtTokenUserA;
    private String jwtTokenUserB;
    private Long userAKeyId;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest userAReq = RegisterRequest.builder()
                .name("Owner A")
                .email("owner_a@example.com")
                .password("password123")
                .build();

        MvcResult resultA = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userAReq)))
                .andExpect(status().isCreated())
                .andReturn();
        jwtTokenUserA = objectMapper.readTree(resultA.getResponse().getContentAsString()).get("accessToken").asText();

        RegisterRequest userBReq = RegisterRequest.builder()
                .name("Attacker B")
                .email("attacker_b@example.com")
                .password("password123")
                .build();

        MvcResult resultB = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userBReq)))
                .andExpect(status().isCreated())
                .andReturn();
        jwtTokenUserB = objectMapper.readTree(resultB.getResponse().getContentAsString()).get("accessToken").asText();

        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("User A Secret Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtTokenUserA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        userAKeyId = keyResponse.getId();
    }

    @Test
    public void testUserBCannotGetApiKeyOfUserA() throws Exception {
        mockMvc.perform(get("/api/keys/" + userAKeyId)
                        .header("Authorization", "Bearer " + jwtTokenUserB))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUserBCannotRevokeApiKeyOfUserA() throws Exception {
        mockMvc.perform(patch("/api/keys/" + userAKeyId + "/revoke")
                        .header("Authorization", "Bearer " + jwtTokenUserB))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUserBCannotRegenerateApiKeyOfUserA() throws Exception {
        mockMvc.perform(post("/api/keys/" + userAKeyId + "/regenerate")
                        .header("Authorization", "Bearer " + jwtTokenUserB))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUserBCannotViewUsageStatsOfUserAKey() throws Exception {
        mockMvc.perform(get("/api/keys/" + userAKeyId + "/usage")
                        .header("Authorization", "Bearer " + jwtTokenUserB))
                .andExpect(status().isNotFound());
    }
}
