package com.uijeong.microblog.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("auth-service", r -> r.path("/api/auth/**").uri("lb://auth-service"))
            .route("member-service", r -> r.path("/api/members/**").uri("lb://member-service"))
            .route("post-service", r -> r.path("/api/posts/**").uri("lb://post-service")).build();
    }
}

