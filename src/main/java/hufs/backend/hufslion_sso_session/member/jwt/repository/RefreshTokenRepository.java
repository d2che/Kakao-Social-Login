package hufs.backend.hufslion_sso_session.member.jwt.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import hufs.backend.hufslion_sso_session.member.jwt.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // 토큰 값으로 조회
    Optional<RefreshToken> findByToken(String token);

    // 특정 회원 ID의 모든 리프레시 토큰 삭제
    void deleteAllByMemberId(Long memberId);
}
