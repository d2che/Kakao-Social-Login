package hufs.backend.hufslion_sso_session.member.jwt.service;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.stereotype.Service;

import hufs.backend.hufslion_sso_session.common.exception.NotFoundException;
import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.jwt.entity.RefreshToken;
import hufs.backend.hufslion_sso_session.member.jwt.repository.RefreshTokenRepository;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final MemberRepository memberRepository;

    @Transactional
    public void saveOrUpdateRefreshToken(Long memberId, String token, LocalDateTime expiresAt, String deviceInfo) {

        Member member = memberRepository.findById(memberId)
                        .orElseThrow(() -> new NotFoundException("존재하지 않는 회원입니다. id= " + memberId));

        // 기존 리프레쉬 토큰 삭제 (단일 세션)
        refreshTokenRepository.deleteAllByMemberId(memberId);

        RefreshToken refreshToken = RefreshToken.builder()
                .member(member)
                .token(token)
                .expiresAt(expiresAt)
                .deviceInfo(deviceInfo)
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void deleteAllByMemberId(Long memberId) {
        refreshTokenRepository.deleteAllByMemberId(memberId);
    }

    public boolean isTokenExpired(RefreshToken refreshToken) {
        return refreshToken.getExpiresAt().isBefore(LocalDateTime.now());
    }
}
