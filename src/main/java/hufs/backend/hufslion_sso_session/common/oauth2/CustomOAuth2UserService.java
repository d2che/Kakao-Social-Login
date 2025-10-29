package hufs.backend.hufslion_sso_session.common.oauth2;

import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Service
@Transactional
@Slf4j
public class CustomOAuth2UserService
	implements org.springframework.security.oauth2.client.userinfo.OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final MemberRepository memberRepository;
	private final HttpSession httpSession;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		log.info("=== OAuth2 로그인 시작 ===");

		org.springframework.security.oauth2.client.userinfo.OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);

		// 현재 로그인 진행 중인 서비스를 구분하는 코드 (네이버 로그인인지 구글 로그인인지 구분)
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		log.info("소셜 제공자: {}", registrationId);

		String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
			.getUserInfoEndpoint().getUserNameAttributeName();

		// OAuth2UserService를 통해 가져온 OAuthUser의 attribute를 담을 클래스 ( 네이버 등 다른 소셜 로그인도 이 클래스 사용)
		OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
			oAuth2User.getAttributes());

		log.info("파싱된 attributes - name: {}, email: {}", attributes.getName(), attributes.getEmail());

		Member member = saveOrUpdate(attributes);
		log.info("최종 사용자 엔티티 - ID: {}, Email: {}", member.getId(), member.getEmail());

		// UserEntity 클래스를 사용하지 않고 SessionUser클래스를 사용하는 이유는 오류 방지.
		httpSession.setAttribute("user", new MemberDTO(member)); // UserDTO : 세션에 사용자 정보를 저장하기 위한 Dto 클래스

		log.info("=== OAuth2 로그인 완료 ===");

		return new DefaultOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority(member.getOauthId())),
			attributes.getAttributes(),
			attributes.getNameAttributeKey());
	}

	private Member saveOrUpdate(OAuthAttributes attributes) {
		Member userEntity = memberRepository.findByOauthId(
				attributes.getSocialProvider() + "_" + attributes.getSocialId())
			.map(entity -> {
				log.info("기존 사용자 발견 - ID: {}, Email: {}", entity.getId(), entity.getEmail());
				return entity.update(attributes.getName());
			})
			.orElseGet(() -> {
				log.info("새 사용자 생성 - Email: {}", attributes.getEmail());
				return attributes.toEntity();
			});

		System.out.println("userEntity = " + userEntity.toString());
		Member savedMember = memberRepository.save(userEntity);
		log.info("저장된 사용자 - ID: {}, Email: {}", savedMember.getId(), savedMember.getEmail());

		return savedMember;
	}
}