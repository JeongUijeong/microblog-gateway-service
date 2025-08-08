package com.uijeong.microblog.gateway.config;

import com.uijeong.microblog.gateway.filter.JwtAuthenticationFilter;
import com.uijeong.microblog.gateway.filter.JwtGatewayFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Gateway 라우터 및 필터 설정
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class RouteLocatorConfig {

    private final JwtGatewayFilter jwtGatewayFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Gateway 라우터
     */
    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder,
        JwtAuthenticationFilter jwtFilter) {
        return builder.routes()
            .route("auth-service", r -> r.path("/api/auth/**")
                .uri("lb://auth-service"))
            .route("member-service", r -> r.path("/api/members/**")
                .filters(f -> f.filter(jwtGatewayFilter))
                .uri("lb://member-service"))
            .route("post-service", r -> r.path("/api/posts/**")
                .filters(f -> f.filter(jwtGatewayFilter))
                .uri("lb://post-service")).build();
    }

    /**
     * Spring Security 필터 체인
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/api/auth/**", "/api/members/signup")
                .permitAll() // 비인증 경로 허용
                .anyExchange().authenticated() // 나머지 요청은 인증 필요
            )
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }
}

