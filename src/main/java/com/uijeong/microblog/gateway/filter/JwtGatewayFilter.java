package com.uijeong.microblog.gateway.filter;

import com.uijeong.microblog.gateway.util.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtGatewayFilter implements GatewayFilter {

    private final JwtProvider jwtProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = extractTokenFromRequest(request);
        if (token != null && jwtProvider.validateToken(token)) {
            Claims claims = jwtProvider.parseClaims(token);

            // 헤더에 사용자 정보를 추가 (옵션: downstream 서비스에서 사용)
            ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Id", claims.getSubject()) // 사용자 식별자
                .header("X-User-Nickname", (String) claims.get("nickname")) // 사용자 닉네임
                .header("X-User-Role", (String) claims.get("role")) // 사용자 역할
                .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        // 토큰 없거나 유효하지 않을 경우 그대로 통과
        return chain.filter(exchange);
    }

    private String extractTokenFromRequest(ServerHttpRequest request) {
        // 일반적으로 Authorization: Bearer {token}
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
