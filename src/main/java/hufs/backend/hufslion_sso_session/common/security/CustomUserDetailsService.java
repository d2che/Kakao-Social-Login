package hufs.backend.hufslion_sso_session.common.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import hufs.backend.hufslion_sso_session.common.security.entity.SecurityMember;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

	private final MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return memberRepository.findByEmail(email)
			.map(SecurityMember::new)
			.orElseThrow(() -> new UsernameNotFoundException("해당 이메일의 회원을 찾을 수 없습니다 : " + email));
	}
}
