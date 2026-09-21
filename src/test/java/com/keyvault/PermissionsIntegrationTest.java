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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class PermissionsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    public void setUp() throws Exception {
        RegisterRequest registerReq = RegisterRequest.builder()
                .name("Perm User")
                .email("perm_user@example.com")
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
    public void testReadOnlyKeyCanReadButCannotWrite() throws Exception {
        CreateApiKeyRequest readKeyReq = CreateApiKeyRequest.builder()
                .name("ReadOnly Key")
                .permissions(Set.of(Permission.READ))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(readKeyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        String rawKey = keyResponse.getApiKey();

        mockMvc.perform(get("/api/protected/read")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Read access granted"));

        mockMvc.perform(post("/api/protected/write")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testReadWriteKeyCanReadAndWrite() throws Exception {
        CreateApiKeyRequest rwKeyReq = CreateApiKeyRequest.builder()
                .name("ReadWrite Key")
                .permissions(Set.of(Permission.READ, Permission.WRITE))
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(rwKeyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(createResult.getResponse().getContentAsString(), CreateApiKeyResponse.class);
        String rawKey = keyResponse.getApiKey();

        mockMvc.perform(get("/api/protected/read")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Read access granted"));

        mockMvc.perform(post("/api/protected/write")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Write access granted"));
    }
}
