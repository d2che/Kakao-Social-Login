package hufs.backend.hufslion_sso_session.common.oauth2;

import java.util.Map;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
public class OAuthAttributes {
	private Map<String, Object> attributes;
	private String nameAttributeKey;
	private String name;
	private String email;
	private String profileImage;
	private String socialProvider;
	private String socialId;

	@Builder
	public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email,
		String profileImage, String socialProvider, String socialId) {
		this.attributes = attributes;
		this.nameAttributeKey = nameAttributeKey;
		this.name = name;
		this.email = email;
		this.profileImage = profileImage;
		this.socialProvider = socialProvider;
		this.socialId = socialId;
	}

	public static OAuthAttributes of(String registrationId, String userNameAttributeName,
		Map<String, Object> attributes) {
		if ("naver".equals(registrationId)) {
			return ofNaver(registrationId, userNameAttributeName, attributes);
		} else if ("kakao".equals(registrationId)) {
			return ofKakao(registrationId, userNameAttributeName, attributes);
		}

		return ofGoogle(registrationId, userNameAttributeName, attributes);
	}

	private static OAuthAttributes ofGoogle(String registrationId, String userNameAttributeName,
		Map<String, Object> attributes) {
		return OAuthAttributes.builder()
			.name((String)attributes.get("name"))
			.email((String)attributes.get("email"))
			.profileImage((String)attributes.get("picture"))
			.attributes(attributes)
			.socialProvider(registrationId)
			.socialId((String)attributes.get("sub"))
			.nameAttributeKey(userNameAttributeName)
			.build();
	}

	private static OAuthAttributes ofNaver(String registrationId, String userNameAttributeName,
		Map<String, Object> attributes) {
		Map<String, Object> response = (Map<String, Object>)attributes.get("response");

		return OAuthAttributes.builder()
			.name((String)response.get("name"))
			.email((String)response.get("email"))
			.profileImage((String)response.get("profile_image"))
			.attributes(attributes)
			.socialProvider(registrationId)
			.socialId((String)response.get("id"))
			.nameAttributeKey(userNameAttributeName)
			.build();
	}

	private static OAuthAttributes ofKakao(String registrationId, String userNameAttributeName,
		Map<String, Object> attributes) {
		log.info("=== 카카오 응답 파싱 시작 ===");
		log.info("전체 attributes keys: {}", attributes.keySet());
		log.info("카카오 사용자 ID: {}", attributes.get("id"));

		Map<String, Object> kakaoAccount = (Map<String, Object>)attributes.get("kakao_account");
		log.info("kakao_account keys: {}", kakaoAccount != null ? kakaoAccount.keySet() : "null");

		Map<String, Object> profile = (Map<String, Object>)kakaoAccount.get("profile");
		log.info("profile keys: {}", profile != null ? profile.keySet() : "null");

		String nickname = (String)profile.get("nickname");
		String email = (String)kakaoAccount.get("email");
		String profileImageUrl = (String)profile.get("profile_image_url");
		String socialId = String.valueOf(attributes.get("id"));

		log.info("파싱 결과 - nickname: {}, email: {}, profileImageUrl: {}, socialId: {}",
			nickname, email, profileImageUrl, socialId);
		log.info("=== 카카오 응답 파싱 완료 ===");

		return OAuthAttributes.builder()
			.name(nickname)
			.email(email)
			.profileImage(profileImageUrl)
			.attributes(attributes)
			.socialProvider(registrationId)
			.socialId(socialId)
			.nameAttributeKey(userNameAttributeName)
			.build();
	}

	public Member toEntity() {
		// 소셜 로그인 사용자의 userId는 소셜제공자_소셜ID 형식으로 생성
		String generatedUserId = socialProvider + "_" + socialId;

		return Member.builder()
			.oauthId(generatedUserId)
			.name(name)
			.email(email)
			.password("OAUTH_USER")
			.build();
	}
}