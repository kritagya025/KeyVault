package com.keyvault.config;

import com.keyvault.entity.ApiKey;
import com.keyvault.entity.User;
import com.keyvault.repository.ApiKeyRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyGenerator apiKeyGenerator;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String rawApiKey = request.getHeader(API_KEY_HEADER);

        if (StringUtils.hasText(rawApiKey)) {
            String keyHash = apiKeyGenerator.hashApiKey(rawApiKey);
            Optional<ApiKey> apiKeyOptional = apiKeyRepository.findByKeyHash(keyHash);

            if (apiKeyOptional.isPresent()) {
                ApiKey apiKey = apiKeyOptional.get();

                boolean isNotRevoked = !apiKey.isRevoked();
                boolean isNotExpired = apiKey.getExpiresAt() == null || apiKey.getExpiresAt().isAfter(LocalDateTime.now());

                if (isNotRevoked && isNotExpired) {
                    User owner = apiKey.getUser();

                    List<SimpleGrantedAuthority> authorities = apiKey.getPermissions().stream()
                            .map(permission -> new SimpleGrantedAuthority("KEY_" + permission.name()))
                            .toList();

                    UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                            owner.getEmail(),
                            owner.getPassword(),
                            authorities
                    );

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    System.out.println("API Key is revoked or expired!");
                }
            } else {
                System.out.println("API Key hash not found in database!");
            }
        }

        filterChain.doFilter(request, response);
    }
}
