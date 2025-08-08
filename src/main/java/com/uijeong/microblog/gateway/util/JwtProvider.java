package com.uijeong.microblog.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * JWT 유효성 검증 유틸 클래스
 */
@Slf4j
@Component
public class JwtProvider {

    // yml에서 주입받은 secret 값을 저장할 변수
    @Value("${jwt.secret}")
    private String secretKey;

    // JWT 토큰의 유효 기간
    private static final long TOKEN_VALIDITY = 1000 * 60 * 60;

    // 암호화 키 객체
    private Key key;

    // Bean 생성 후, 시크릿 키를 기반으로 Key 객체 초기화
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public Collection<SimpleGrantedAuthority> getAuthorities(List<String> roles) {
        return roles.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
    }

    /**
     * 토큰 유효성 검사
     *
     * @param token 검사할 토큰
     * @return 검사 결과
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)          // 서명 키 설정
                .build()
                .parseClaimsJws(token);      // 실제로 토큰 파싱 시도

            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.warn("JWT 포맷이 유효하지 않습니다.");
        } catch (ExpiredJwtException e) {
            log.warn("JWT 토큰이 만료되었습니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims(페이로드) 문자열이 비어있습니다.");
        }
        return false;
    }

    /**
     * 내부적으로 JWT에서 Claims(페이로드)만 추출
     *
     * @param token JWT 문자열
     * @return Claims 객체
     */
    public Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token) // JWS 형태의 JWT만 허용 (서명 검증)
                .getBody();
        } catch (ExpiredJwtException e) {
            // 토큰이 만료됐더라도 Claims는 꺼낼 수 있으므로 따로 처리
            return e.getClaims();
        }
    }
}
