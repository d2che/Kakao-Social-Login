package hufs.backend.hufslion_sso_session.common.oauth2;

import java.util.Map;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import lombok.Builder;
import lombok.Getter;

@Getter
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
		Map<String, Object> kakaoAccount = (Map<String, Object>)attributes.get("kakao_account");
		Map<String, Object> profile = (Map<String, Object>)kakaoAccount.get("profile");

		return OAuthAttributes.builder()
			.name((String)profile.get("nickname"))
			.email((String)kakaoAccount.get("email"))
			.profileImage((String)profile.get("profile_image_url"))
			.attributes(attributes)
			.socialProvider(registrationId)
			.socialId(String.valueOf(attributes.get("id")))
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