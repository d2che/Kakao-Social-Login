package hufs.backend.hufslion_sso_session.common.oauth2;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.jwt.service.JwtService;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final JwtService jwtService;
	private final MemberRepository memberRepository;

	// 프론트엔드 URL (환경에 따라 설정)
	@Value("${app.oauth2.authorized-redirect-uri:http://localhost:3000}")
	private String redirectUri;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException {

		log.info("=================================");
		log.info("=== OAuth2 인증 성공 핸들러 시작 ===");
		log.info("=================================");

		OAuth2User oauth2User = (OAuth2User)authentication.getPrincipal();

		log.info("OAuth2User attributes: {}", oauth2User.getAttributes());
		log.info("OAuth2User authorities: {}", oauth2User.getAuthorities());

		// CustomOAuth2UserService에서 authorities에 oauthId를 넣어줌
		String oauthId = oauth2User.getAuthorities().stream()
			.findFirst()
			.map(authority -> authority.getAuthority())
			.orElseThrow(() -> new IllegalStateException("OAuth2User에 권한 정보가 없습니다."));

		log.info("=== 추출된 OAuthId ===");
		log.info("oauthId: {}", oauthId);

		// 데이터베이스에서 사용자 조회
		Member member = memberRepository.findByOauthId(oauthId)
			.orElseThrow(() -> new IllegalStateException("사용자를 찾을 수 없습니다."));

		log.info("=== DB 조회된 사용자 ===");
		log.info("Member ID: {}", member.getId());
		log.info("Email: {}", member.getEmail());
		log.info("Name: {}", member.getName());
		log.info("OAuthId: {}", member.getOauthId());

		// JWT 토큰 생성
		log.info("=== JWT 토큰 생성 시작 ===");
		String accessToken = jwtService.createAccessToken(member);
		String refreshToken = jwtService.createRefreshToken(member.getId());

		log.info("AccessToken 생성 완료 : {}...", accessToken.substring(0, Math.min(50, accessToken.length())));
		log.info("RefreshToken 생성 완료 : {}...", refreshToken.substring(0, Math.min(50, refreshToken.length())));

		String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
			.queryParam("token", accessToken)
			.queryParam("refresh", refreshToken)
			.build().toUriString();

		log.info("=== 리다이렉트 ===");
		log.info("리다이렉트 기본 URL: {}", redirectUri);
		log.info("전체 리다이렉트 URL (토큰 포함, 앞부분): {}...", targetUrl.substring(0, Math.min(100, targetUrl.length())));

		response.sendRedirect(targetUrl);

		log.info("=== OAuth2 인증 성공 핸들러 완료 ===");
	}
}
