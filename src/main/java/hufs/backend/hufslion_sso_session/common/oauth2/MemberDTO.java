package hufs.backend.hufslion_sso_session.common.oauth2;

import java.io.Serializable;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import lombok.Getter;

@Getter
public class MemberDTO implements Serializable {
	private String name;
	private String email;

	public MemberDTO(Member userEntity) {
		this.name = userEntity.getName();
		this.email = userEntity.getEmail();
	}
}