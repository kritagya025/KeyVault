package com.keyvault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link JwtUtils}. */
class JwtUtilsTest {

    private static final String SECRET = "keyvault-unit-test-signing-secret-0123456789abcdef";
    private static final String OTHER_SECRET = "a-completely-different-signing-secret-fedcba9876543210";
    private static final long ONE_DAY_MS = 86_400_000L;

    @Test
    @DisplayName("A generated token round-trips back to the subject email")
    void generatedTokenRoundTrips() {
        JwtUtils jwtUtils = new JwtUtils(SECRET, ONE_DAY_MS);

        String token = jwtUtils.generateToken("member@example.com");

        assertTrue(jwtUtils.validateToken(token));
        assertEquals("member@example.com", jwtUtils.getEmailFromToken(token));
    }

    @Test
    @DisplayName("Malformed input is rejected instead of throwing")
    void malformedTokenIsInvalid() {
        JwtUtils jwtUtils = new JwtUtils(SECRET, ONE_DAY_MS);

        assertFalse(jwtUtils.validateToken("not-a-jwt"));
        assertFalse(jwtUtils.validateToken(""));
    }

    @Test
    @DisplayName("A token signed with a different secret is rejected")
    void tokenFromAnotherSecretIsInvalid() {
        String foreignToken = new JwtUtils(OTHER_SECRET, ONE_DAY_MS).generateToken("member@example.com");

        assertFalse(new JwtUtils(SECRET, ONE_DAY_MS).validateToken(foreignToken));
    }

    @Test
    @DisplayName("An expired token is rejected")
    void expiredTokenIsInvalid() {
        JwtUtils expiringImmediately = new JwtUtils(SECRET, -1_000L);

        String token = expiringImmediately.generateToken("member@example.com");

        assertFalse(expiringImmediately.validateToken(token));
    }

    @Test
    @DisplayName("A secret shorter than 256 bits is refused at startup with an actionable message")
    void shortSecretIsRejected() {
        IllegalStateException failure =
                assertThrows(IllegalStateException.class, () -> new JwtUtils("too-short", ONE_DAY_MS));

        assertTrue(failure.getMessage().contains("at least 32 bytes"));
    }

    @Test
    @DisplayName("With no configured secret an ephemeral key is generated so local runs still work")
    void blankSecretFallsBackToEphemeralKey() {
        JwtUtils first = new JwtUtils("", ONE_DAY_MS);
        JwtUtils second = new JwtUtils("   ", ONE_DAY_MS);

        String token = first.generateToken("member@example.com");

        assertTrue(first.validateToken(token));
        // Each instance generates its own key, which is exactly why this must not be used in production.
        assertFalse(second.validateToken(token));
    }
}
