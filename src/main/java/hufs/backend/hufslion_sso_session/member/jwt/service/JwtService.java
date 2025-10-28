package hufs.backend.hufslion_sso_session.member.jwt.service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class JwtService {

    private final SecretKey secretKey;
    private final Long accessTokenExpirePeriod;
    private final Long refreshTokenExpirePeriod;
    private final RefreshTokenService refreshTokenService;

    public JwtService(@Value("${jwt.secretKey}") String secretKey,
                      @Value("${jwt.access.expiration}") Long accessTokenExpirePeriod,
                      @Value("${jwt.refresh.expiration}") Long refreshTokenExpirePeriod,
                      RefreshTokenService refreshTokenService) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpirePeriod = accessTokenExpirePeriod;
        this.refreshTokenExpirePeriod = refreshTokenExpirePeriod;
        this.refreshTokenService = refreshTokenService;
    }

    // Access Token 발급
    public String createAccessToken(Member member) {

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + accessTokenExpirePeriod);

        return Jwts.builder()
                .setSubject(member.getId().toString())    // sub
                .claim("email", member.getEmail())
                .claim("type", "ACCESS")
                .setIssuedAt(now)                   // iat
                .setExpiration(expirationDate)      // exp
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
    
    // Refresh Token 발급
    public String createRefreshToken(Long memberId) {

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + refreshTokenExpirePeriod);

        String token =  Jwts.builder()
                .setSubject(memberId.toString())    // sub
                .claim("type", "REFRESH")
                .setIssuedAt(now)                   // iat
                .setExpiration(expirationDate)      // exp
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();

        refreshTokenService.deleteAllByMemberId(memberId);

        refreshTokenService.saveOrUpdateRefreshToken(
                memberId,
                token,
                expirationDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime(),
                null
        );

        return token;
    }
    
    // Access + Refresh Token 발급
    public Map<String, String> createAccessAndRefreshToken(Member member) {

        String accessToken = createAccessToken(member);
        String refreshToken = createRefreshToken(member.getId());

        log.debug("Access/Refresh Token 발급 완료 : {}", member.getId());

        return Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );
    }

    /***
     * 토큰 유효성 검증 메서드
     * @param token 검증할 토큰
     * @return 리턴 시 유효, false 시 무효
     */
    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰입니다 : {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("지원하지 않는 토큰입니다 : {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("잘못된 토큰입니다 : {}", e.getMessage());
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("유효하지 않은 토큰입니다 : {}", e.getMessage());
        }
        return false;
    }
    
    // 토큰 클레임 추출
    private Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    // 토큰에서 이메일 추출
    public Optional<String> extractEmail(String accessToken) {
        try {
            return Optional.ofNullable(getClaimsFromToken(accessToken).get("email", String.class));
        } catch (Exception e) {
            log.error("토큰에서 이메일 추출 실패 : {}", e.getMessage());
            return Optional.empty();
        }
    }
    
    // 토큰에서 권한 추출
    public Optional<String> extractRole(String accessToken) {
        try {
            return Optional.ofNullable(getClaimsFromToken(accessToken).get("role", String.class));
        } catch (Exception e) {
            log.error("토큰에서 권한 추출 실패 : {}", e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<Long> extractMemberId(String accessToken) {
        try {
            String sub = getClaimsFromToken(accessToken).getSubject();
            return Optional.ofNullable(sub)
                    .map(Long::valueOf);
        } catch (Exception e) {
            log.error("토큰에서 MemberId 추출 실패: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
