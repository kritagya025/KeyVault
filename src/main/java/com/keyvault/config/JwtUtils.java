package com.keyvault.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * Utility component for generating, parsing, and validating JSON Web Tokens (JWT).
 */
@Component
public class JwtUtils {

    /** HMAC-SHA keys must be at least as long as the digest they sign with (256 bits). */
    private static final int MIN_SECRET_BYTES = 32;

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    private final SecretKey key;
    private final long jwtExpirationMs;

    public JwtUtils(
            @Value("${jwt.secret:}") String secret,
            @Value("${jwt.expiration}") long jwtExpirationMs
    ) {
        this.key = resolveKey(secret);
        this.jwtExpirationMs = jwtExpirationMs;
    }

    /**
     * Builds the signing key from configuration, falling back to a freshly generated
     * ephemeral key when no secret is supplied. The fallback keeps local development
     * runnable without committing a secret, at the cost of invalidating every issued
     * token on restart — which is why it is never appropriate in a deployed environment.
     */
    private static SecretKey resolveKey(String secret) {
        if (!StringUtils.hasText(secret)) {
            log.warn("No jwt.secret configured; generating an ephemeral signing key. "
                    + "All issued tokens become invalid on restart. "
                    + "Set the JWT_SECRET environment variable before deploying.");
            return Jwts.SIG.HS256.key().build();
        }

        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "jwt.secret must be at least " + MIN_SECRET_BYTES + " bytes (got " + secretBytes.length + "). "
                            + "Generate one with: openssl rand -hex 32");
        }
        return Keys.hmacShaKeyFor(secretBytes);
    }

    /**
     * Generates a signed JWT access token for the given user email.
     *
     * @param email the user's email subject
     * @return compact URL-safe JWT string
     */
    public String generateToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
