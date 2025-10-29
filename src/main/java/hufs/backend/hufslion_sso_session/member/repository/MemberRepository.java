package hufs.backend.hufslion_sso_session.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import hufs.backend.hufslion_sso_session.member.entity.Member;

@Repository
public interface MemberRepository extends JpaRepository<Member, String> {
    Optional<Member> findById(Long id);
    Optional<Member> findByEmail(String email);
    Optional<Member> findByOauthId(String oauthId);
}
