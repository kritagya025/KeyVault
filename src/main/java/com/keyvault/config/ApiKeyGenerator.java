package com.keyvault.config;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility component responsible for generating secure raw API keys
 * and computing one-way SHA-256 cryptographic hashes.
 */
@Component
public class ApiKeyGenerator {

    private static final String PREFIX = "kv_live_";
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a cryptographically secure raw API key prefixed with {@code kv_live_}.
     *
     * @return a unique raw API key string
     */
    public String generateRawApiKey() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return PREFIX + encoded;
    }

    /**
     * Computes the SHA-256 hex digest of a raw API key.
     *
     * @param rawKey the raw API key to hash
     * @return hex-encoded SHA-256 hash string
     */
    public String hashApiKey(String rawKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawKey.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
