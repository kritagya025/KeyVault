package com.keyvault.config;

import jakarta.servlet.Filter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot auto-registers every {@link jakarta.servlet.Filter} bean with the servlet
 * container. These three filters are wired explicitly into the Spring Security chain by
 * {@link SecurityConfig}, so the container-level copies are disabled here. Without this,
 * each filter is registered twice with an implicit ordering relationship between the two
 * registrations, and authentication would depend on the security chain happening to run first.
 */
@Configuration
public class FilterRegistrationConfig {

    @Bean
    public FilterRegistrationBean<ApiKeyAuthenticationFilter> apiKeyAuthenticationFilterRegistration(
            ApiKeyAuthenticationFilter filter) {
        return disableContainerRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration(
            JwtAuthenticationFilter filter) {
        return disableContainerRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<ApiUsageFilter> apiUsageFilterRegistration(ApiUsageFilter filter) {
        return disableContainerRegistration(filter);
    }

    private <T extends Filter> FilterRegistrationBean<T> disableContainerRegistration(T filter) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
