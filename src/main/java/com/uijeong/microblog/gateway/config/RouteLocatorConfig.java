package com.uijeong.microblog.gateway.config;

import com.uijeong.microblog.gateway.filter.JwtAuthenticationFilter;
import com.uijeong.microblog.gateway.filter.JwtGatewayFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            // 인증/인가 서비스 라우팅 설정
            .route("auth-service", r -> r.path("/api/auth/**")
                .uri("lb://auth-service"))
            // 회원가입 라우팅 설정
            .route("member-service-signup", r -> r.path("/api/members")
                .filters(GatewayFilterSpec::filters) // 필터 안 거침
                .uri("lb://member-service"))
            // 회원가입을 제외한 사용자 관련 API 라우팅 설정
            .route("member-service-auth", r -> r.path("/api/members/**")
                .filters(f -> f.filter(jwtGatewayFilter))
                .uri("lb://member-service"))
            // 게시물 서비스 라우팅 설정
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
            // CSRF(Cross-Site Request Forgery) 보호 비활성화(토큰 기반 인증 사용할 것)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            // HTTP Basic 인증 비활성화(기본 브라우저 로그인 팝업 사용 X)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            // 폼 로그인 비활성화(스프링 시큐리티 기본 로그인 폼 사용 X, JWT 커스텀 인증 O)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/internal/**").permitAll() // 내부 호출은 인증 X
                .pathMatchers(HttpMethod.POST, "/api/members").permitAll() // 회원가입은 인증 X
                .pathMatchers("/api/auth/login").permitAll() // 로그인은 인증 X
                .anyExchange().authenticated() // 나머지 요청은 인증 필요
            )
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }
}

