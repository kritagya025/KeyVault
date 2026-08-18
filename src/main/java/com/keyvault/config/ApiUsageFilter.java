package com.keyvault.config;

import com.keyvault.entity.ApiKey;
import com.keyvault.service.ApiUsageService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class ApiUsageFilter extends OncePerRequestFilter {

    private final ApiUsageService apiUsageService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            Object apiKeyAttr = request.getAttribute(ApiKeyAuthenticationFilter.AUTHENTICATED_API_KEY_ATTR);
            if (apiKeyAttr instanceof ApiKey apiKey) {
                int statusCode = response.getStatus();
                boolean successful = statusCode >= 200 && statusCode < 400;

                apiUsageService.recordUsage(
                        apiKey,
                        request.getRequestURI(),
                        request.getMethod(),
                        statusCode,
                        successful
                );
            }
        }
    }
}
