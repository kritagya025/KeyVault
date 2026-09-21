package com.keyvault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Guards the security rules the dashboard depends on: its static shell must be reachable
 * without a token (otherwise the login form itself would 401), while every API route stays
 * protected. The dashboard authenticates against /api/** like any other client.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class DashboardAccessIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("The dashboard shell is served without authentication")
    public void testStaticAssetsArePublic() throws Exception {
        for (String asset : new String[]{"/index.html", "/css/styles.css", "/js/app.js",
                "/js/api.js", "/js/auth.js", "/js/dom.js", "/js/keys.js", "/js/usage.js"}) {
            mockMvc.perform(get(asset)).andExpect(status().isOk());
        }
    }

    @Test
    @DisplayName("Serving the dashboard does not open up the API")
    public void testApiRemainsProtected() throws Exception {
        mockMvc.perform(get("/api/keys")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/protected/hello")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/protected/read")).andExpect(status().isUnauthorized());
    }
}
