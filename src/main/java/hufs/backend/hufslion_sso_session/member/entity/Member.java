package hufs.backend.hufslion_sso_session.member.entity;

import java.util.ArrayList;
import java.util.List;

import hufs.backend.hufslion_sso_session.common.entity.BaseTimeEntity;
import hufs.backend.hufslion_sso_session.member.jwt.entity.RefreshToken;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "member")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder(toBuilder = true)
@EqualsAndHashCode(of = "id", callSuper = false)
public class Member extends BaseTimeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// 가입 이메일(유니크)
	@Column(nullable = false, unique = true, length = 100)
	private String email;

	// 비밀번호 (OAuth 사용시 nullable)
	@Column(nullable = true, length = 255)
	private String password;

	// 소셜 로그인 유니크 키(구글 ID 등)
	@Column(nullable = true, unique = true, length = 100)
	private String oauthId;

	// 회원명(본명)
	@Column(nullable = false, length = 10)
	private String name;

	// Member - RefreshToken, 1:N on Member perspective
	@OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
	@Builder.Default
	private List<RefreshToken> refreshTokens = new ArrayList<>();

	public void changeEmail(String newEmail) {
		this.email = newEmail;
	}

	public void updateOauthId(String newOauthId) {
		this.oauthId = newOauthId;
	}

	// 리프레쉬 토큰 추가
	public void addRefreshToken(RefreshToken newRefreshToken) {
		this.refreshTokens.add(newRefreshToken);
	}

	// 리프레쉬 토큰 삭제
	public void removeRefreshToken(RefreshToken newRefreshToken) {
		this.refreshTokens.remove(newRefreshToken);
	}

	public Member update(String name) {
		this.name = name;
		return this;
	}

	@Override
	public String toString() {
		return "Member{" +
			"id=" + id +
			", email='" + email + '\'' +
			", password='" + password + '\'' +
			", oauthId='" + oauthId + '\'' +
			", name='" + name + '\'' +
			", refreshTokens=" + refreshTokens +
			", createdAt=" + createdAt +
			", updatedAt=" + updatedAt +
			'}';
	}
}
