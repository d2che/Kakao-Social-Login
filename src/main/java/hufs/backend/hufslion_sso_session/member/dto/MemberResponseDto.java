package hufs.backend.hufslion_sso_session.member.dto;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "회원 정보 응답 DTO")
public class MemberResponseDto {

	@Schema(description = "회원 ID", example = "1")
	private Long id;

	@Schema(description = "이메일", example = "user@example.com")
	private String email;

	@Schema(description = "이름", example = "홍길동")
	private String name;

	@Schema(description = "OAuth ID", example = "kakao_12345678")
	private String oauthId;

	public static MemberResponseDto from(Member member) {
		return MemberResponseDto.builder()
			.id(member.getId())
			.email(member.getEmail())
			.name(member.getName())
			.oauthId(member.getOauthId())
			.build();
	}
}