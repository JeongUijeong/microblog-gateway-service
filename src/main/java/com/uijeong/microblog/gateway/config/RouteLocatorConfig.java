package com.uijeong.microblog.gateway.config;

import com.uijeong.microblog.gateway.filter.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Gateway 라우터 및 필터 설정
 */
@Configuration
public class RouteLocatorConfig {

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder, JwtAuthenticationFilter jwtFilter) {
        return builder.routes()
            .route("auth-service", r -> r.path("/api/auth/**")
                .uri("lb://auth-service"))
            .route("member-service", r -> r.path("/api/members/**")
                .filters(f -> f.filter(jwtFilter.apply(new Object())))
                .uri("lb://member-service"))
            .route("post-service", r -> r.path("/api/posts/**")
                .filters(f -> f.filter(jwtFilter.apply(new Object())))
                .uri("lb://post-service")).build();
    }
}

