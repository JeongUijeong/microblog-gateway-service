package com.uijeong.microblog.gateway.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JWT 유효성 검증 유틸 클래스
 */
@Slf4j
@Component
public class JwtValidator {

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
}
