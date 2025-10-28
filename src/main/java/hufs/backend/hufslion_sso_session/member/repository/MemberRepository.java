package hufs.backend.hufslion_sso_session.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.entity.Type;

@Repository
public interface MemberRepository extends JpaRepository<Member, String> {
    Optional<Member> findById(Long id);
    Optional<Member> findByEmail(String email);
    Optional<Member> findByOauthId(String oauthId);
}
