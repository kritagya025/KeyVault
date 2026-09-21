package com.keyvault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link ApiKeyGenerator}. */
class ApiKeyGeneratorTest {

    /** Well-known SHA-256 digest of the string "abc". */
    private static final String SHA256_OF_ABC =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private final ApiKeyGenerator generator = new ApiKeyGenerator();

    @Test
    @DisplayName("Generated keys carry the kv_live_ prefix and enough entropy to be unguessable")
    void generatesPrefixedKeysWithEntropy() {
        String rawKey = generator.generateRawApiKey();

        assertTrue(rawKey.startsWith("kv_live_"), "Expected the kv_live_ prefix but got: " + rawKey);
        // 32 random bytes base64url-encoded without padding is 43 characters.
        assertEquals(43, rawKey.substring("kv_live_".length()).length());
    }

    @Test
    @DisplayName("Generated keys do not repeat")
    void generatesDistinctKeys() {
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < 1_000; i++) {
            keys.add(generator.generateRawApiKey());
        }

        assertEquals(1_000, keys.size(), "Generated keys must be unique");
    }

    @Test
    @DisplayName("Hashing matches the published SHA-256 digest and is hex encoded")
    void hashMatchesKnownSha256Vector() {
        String hash = generator.hashApiKey("abc");

        assertEquals(SHA256_OF_ABC, hash);
        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"), "Hash must be lowercase hex");
    }

    @Test
    @DisplayName("Hashing is deterministic and never returns the raw key")
    void hashIsDeterministicAndOneWay() {
        String rawKey = generator.generateRawApiKey();

        assertEquals(generator.hashApiKey(rawKey), generator.hashApiKey(rawKey));
        assertNotEquals(rawKey, generator.hashApiKey(rawKey));
        assertNotEquals(generator.hashApiKey(rawKey), generator.hashApiKey(generator.generateRawApiKey()));
    }

    @Test
    @DisplayName("Leading zero bytes are zero padded rather than truncated")
    void hashPadsLeadingZeroBytes() {
        // SHA-256 of "286" begins with a zero byte, which a naive hex encoder would drop.
        String hash = generator.hashApiKey("286");

        assertEquals(64, hash.length(), "A digest with a leading zero byte must still be 64 characters");
        assertTrue(hash.startsWith("00"));
    }
}
