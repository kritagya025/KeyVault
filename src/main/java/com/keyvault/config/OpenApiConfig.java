package com.keyvault.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("KeyVault API Key Management & Access Control Platform")
                        .version("1.4.0")
                        .description("Enterprise-grade Spring Boot service for developer authentication, hashed key persistence, CIDR/IP whitelisting, metadata tagging & descriptions, sliding-window rate limiting, zero-downtime key rotation, API key validity renewal, EXPIRING_SOON filtering, bulk key revocation/deletion, immutable audit trails, CSV key catalog/audit exports, and account-wide usage analytics & exports.")
                        .contact(new Contact().name("KeyVault Platform Engineering")))
                .components(new Components()
                        .addSecuritySchemes("BearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT Bearer token obtained from POST /api/auth/login or POST /api/auth/register"))
                        .addSecuritySchemes("ApiKeyAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-Key")
                                .description("API Key passed in X-API-Key header to authenticate requests to protected endpoints")));
    }
}
