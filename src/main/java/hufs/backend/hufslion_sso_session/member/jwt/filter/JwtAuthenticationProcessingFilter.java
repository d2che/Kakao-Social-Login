package hufs.backend.hufslion_sso_session.member.jwt.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import hufs.backend.hufslion_sso_session.common.response.ApiResponse;
import hufs.backend.hufslion_sso_session.common.response.SuccessStatus;
import hufs.backend.hufslion_sso_session.common.security.entity.SecurityMember;
import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.jwt.entity.RefreshToken;
import hufs.backend.hufslion_sso_session.member.jwt.repository.RefreshTokenRepository;
import hufs.backend.hufslion_sso_session.member.jwt.service.JwtService;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    @Value("${jwt.access.header}")
    private String accessTokenHeader;

    @Value("${jwt.refresh.header}")
    private String refreshTokenHeader;

    private static final String TOKEN_REISSUE_URL = "/api/v1/member/token-reissue";

    private final JwtService jwtService;
    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    // 필터링 제외 목록
    public static final String[] NOT_FILTER_URLS = {
            "/api/swagger-resources/**",
            "/api/swagger-ui/**",
            "/api/swagger-ui.html",
            "/api/v3/api-docs/**",
            "/v3/api-docs/**",
            "/swagger-resources/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/api/webjars/**",
            "/webjars/**",
            "/oauth2/authorization/**",
            "/login/oauth2/code/**"
    };

    /// 엔드포인트 필터링 제외
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestURI = request.getRequestURI();

        log.info("JwtFilter shouldNotFilter 프로세싱 요청: {}", requestURI);

        for (String url : NOT_FILTER_URLS) {
            // 와일드카드 패턴 처리
            String pattern = url.replace("/**", "");
            if (requestURI.startsWith(pattern)) {
                return true;
            }
        }

        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("=================================");
        log.info("=== JWT 인증 필터 시작 ===");
        log.info("=================================");

        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.info("요청 URI: {} {}", method, requestURI);
        log.info("AccessToken 헤더 이름: {}", accessTokenHeader);
        log.info("RefreshToken 헤더 이름: {}", refreshTokenHeader);

        try {
            if (requestURI.equals(TOKEN_REISSUE_URL)) {
                log.info("=== 토큰 재발급 요청 감지 ===");

                // 리프레쉬 토큰 요청 헤더에서 추출 후 유효성 검사
                Optional<String> refreshTokenOpt = extractToken(request, refreshTokenHeader)
                        .filter(jwtService::isTokenValid);

                if (refreshTokenOpt.isPresent()) {
                    String token = refreshTokenOpt.get();
                    log.info("RefreshToken 추출 성공 (앞부분 30자): {}...", token.substring(0, Math.min(30, token.length())));
                } else {
                    log.warn("RefreshToken이 없거나 유효하지 않음");
                }

                // 리프레쉬 토큰이 비어있다면 예외
                if (refreshTokenOpt.isEmpty()) {
                    throw new JwtException("유효하지 않거나 존재하지 않는 리프레쉬 토큰입니다.");
                }

                String refreshToken = refreshTokenOpt.get();

                // 리프레쉬 토큰으로 새 토큰 발급 후 인증 컨텍스트 설정
                handleRefreshToken(response, refreshToken);

                log.info("=== 토큰 재발급 완료 ===");
                return;
            }

            // 액세스 토큰 요청 헤더에서 추출 후 유효성 검사, 인증 컨텍스트 설정
            log.info("=== AccessToken 인증 처리 ===");
            Optional<String> accessTokenOpt = extractToken(request, accessTokenHeader)
                    .filter(jwtService::isTokenValid);

            if (accessTokenOpt.isPresent()) {
                String token = accessTokenOpt.get();
                log.info("AccessToken 추출 성공 : {}...", token.substring(0, Math.min(30, token.length())));

                accessTokenOpt.ifPresent(accessToken -> {
                    Optional<String> emailOpt = jwtService.extractEmail(accessToken);
                    if (emailOpt.isPresent()) {
                        String email = emailOpt.get();
                        log.info("토큰에서 추출된 이메일: {}", email);

                        Optional<Member> memberOpt = memberRepository.findByEmail(email);
                        if (memberOpt.isPresent()) {
                            Member member = memberOpt.get();
                            log.info("DB에서 회원 조회 성공 - ID: {}, Email: {}", member.getId(), member.getEmail());
                            setAuthentication(member);
                            log.info("SecurityContext에 인증 정보 설정 완료");
                        } else {
                            log.warn("DB에 해당 이메일의 회원이 없음: {}", email);
                        }
                    } else {
                        log.warn("토큰에서 이메일 추출 실패");
                    }
                });
            } else {
                log.info("AccessToken이 없거나 유효하지 않음 (인증 없이 진행)");
            }

            // 이후 필터 체인 진행
            log.info("=== JWT 필터 완료, 다음 필터로 진행 ===");
            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            // 필터단에서 발생하는 예외를 적절한 타이의 예외로 포장하여 상위로 던짐
            // -> FilterExceptionHandler
            log.error("=== JWT 필터 예외 발생 ===");
            log.error("예외 타입: {}", ex.getClass().getName());
            log.error("예외 메시지: {}", ex.getMessage(), ex);
            if (ex instanceof ServletException) {
                throw (ServletException) ex;
            } else if (ex instanceof IOException) {
                throw (IOException) ex;
            }  else {
                throw new ServletException(ex);
            }
        }
    }

    /// Refresh Token을 처리하여 Access Token 재발급 및 인증 처리
    private void handleRefreshToken(HttpServletResponse response, String refreshToken) throws IOException {

        log.info("=== RefreshToken으로 새 토큰 발급 시작 ===");
        log.info("DB에서 RefreshToken 조회 중...");

        RefreshToken savedRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new JwtException("저장된 리프레쉬 토큰이 없습니다."));

        log.info("DB에서 RefreshToken 조회 성공");
        log.info("토큰 만료 시각: {}", savedRefreshToken.getExpiresAt());
        log.info("현재 시각: {}", LocalDateTime.now());

        // 토큰 만료 여부 검사, 만료 시 예외 발생
        if (savedRefreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.error("RefreshToken이 만료됨!");
            throw new JwtException("만료된 리프레쉬 토큰입니다.");
        }

        log.info("토큰 유효성 검사 통과");

        Member member = savedRefreshToken.getMember();
        log.info("토큰 소유자 - ID: {}, Email: {}", member.getId(), member.getEmail());

        // 새로운 Access, Refresh Token 생성
        log.info("새로운 Access & Refresh Token 생성 중...");
        Map<String, String> newTokens = jwtService.createAccessAndRefreshToken(member);
        log.info("새 토큰 생성 완료");

        // 응답 코드와 컨텐츠 타입 설정
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");

        // 새로 발급한 토큰을 응답 헤더에 담아 전송
        response.setHeader(accessTokenHeader, "Bearer " + newTokens.get("accessToken"));
        response.setHeader(refreshTokenHeader, "Bearer " + newTokens.get("refreshToken"));
        log.info("응답 헤더에 새 토큰 설정 완료");

        // 응답 바디 메시지 작성
        String json = new ObjectMapper().writeValueAsString(
			ApiResponse.success(SuccessStatus.TOKEN_REISSUE_SUCCESS, newTokens));
        response.getWriter().write(json);

        setAuthentication(member);
        log.info("SecurityContext에 인증 정보 설정 완료");

        log.info("=== Access, Refresh Token 재발급 완료 ===");
    }

    /// 토큰 추출 유틸 메서드
    private Optional<String> extractToken(HttpServletRequest request, String header) {

        String bearerToken = request.getHeader(header);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return Optional.of(bearerToken.substring(7));
        }

        return Optional.empty();
    }

    /// Member -> SecurityMember 로 생성 후 SecurityContext 에 등록
    private void setAuthentication(Member member) {

        SecurityMember securityMember = SecurityMember.from(member);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                securityMember, null, securityMember.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
