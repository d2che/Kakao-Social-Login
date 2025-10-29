package hufs.backend.hufslion_sso_session.member.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import hufs.backend.hufslion_sso_session.common.exception.UnauthorizedException;
import hufs.backend.hufslion_sso_session.common.response.ApiResponse;
import hufs.backend.hufslion_sso_session.common.response.ErrorStatus;
import hufs.backend.hufslion_sso_session.common.response.SuccessStatus;
import hufs.backend.hufslion_sso_session.common.security.entity.SecurityMember;
import hufs.backend.hufslion_sso_session.member.dto.MemberResponseDto;
import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.jwt.entity.RefreshToken;
import hufs.backend.hufslion_sso_session.member.jwt.service.JwtService;
import hufs.backend.hufslion_sso_session.member.jwt.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@Tag(name = "Member", description = "Member 관련 API 입니다.")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/member")
public class MemberController {

	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService;

	@Operation(
		summary = "액세스 토큰 재발급",
		description = "만료된 액세스 토큰을 재발급합니다. 요청 헤더에 'X-Refresh-Token'으로 유효한 리프레시 토큰을 포함해야 합니다."
			+ "[주의] Swagger 로 테스트 시 토큰 앞에 'Bearer ' 을 붙여야 함.",
		security = @SecurityRequirement(name = "X-Refresh-Token")
	)
	@ApiResponses({
		@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "토큰 재발급 성공"),
		@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "리프레쉬 토큰이 없거나 유효하지 않습니다."),
		@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "회원 정보가 존재하지 않습니다.")
	})
	@GetMapping("/token-reissue")
	public ResponseEntity<ApiResponse<Map<String, String>>> reissueToken(
		@RequestHeader(value = "X-Refresh-Token", required = false) String refreshToken) {

		// 리프레쉬 토큰이 존재하지 않을 경우 예외 처리
		if (refreshToken == null || refreshToken.isEmpty()) {
			throw new UnauthorizedException(ErrorStatus.UNAUTHORIZED_EMPTY_TOKEN.getMessage());
		}

		// "Bearer " 문자열 제거 후 토큰 검증
		String pureRefreshToken = refreshToken.substring(7);
		if (!jwtService.isTokenValid(pureRefreshToken)) {
			throw new UnauthorizedException(ErrorStatus.UNAUTHORIZED_INVALID_TOKEN.getMessage());
		}

		// DB에서 리프레쉬 토큰 존재여부 및 만료 확인
		RefreshToken savedRefreshToken = refreshTokenService.findByToken(pureRefreshToken)
			.orElseThrow(() -> new UnauthorizedException(ErrorStatus.UNAUTHORIZED_INVALID_TOKEN.getMessage()));

		if (refreshTokenService.isTokenExpired(savedRefreshToken)) {
			throw new UnauthorizedException(ErrorStatus.UNAUTHORIZED_TOKEN_EXPIRED.getMessage());
		}

		Member member = savedRefreshToken.getMember();

		// 새 Access, Refresh Token 생성 후 발급
		Map<String, String> newTokens = jwtService.createAccessAndRefreshToken(member);

		return ApiResponse.success(SuccessStatus.TOKEN_REISSUE_SUCCESS, newTokens);
	}

	@Operation(
		summary = "내 정보 조회",
		description = "현재 로그인한 사용자의 정보를 조회합니다. Authorization 헤더에 유효한 액세스 토큰을 포함해야 합니다.",
		security = @SecurityRequirement(name = "Authorization")
	)
	@ApiResponses({
		@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "내 정보 조회 성공"),
		@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자입니다.")
	})
	@GetMapping("/me")
	public ResponseEntity<ApiResponse<MemberResponseDto>> getMyInfo(
		@AuthenticationPrincipal SecurityMember securityMember) {

		if (securityMember == null) {
			throw new UnauthorizedException(ErrorStatus.UNAUTHORIZED_INVALID_TOKEN.getMessage());
		}

		Member member = securityMember.getMember();
		MemberResponseDto response = MemberResponseDto.from(member);

		return ApiResponse.success(SuccessStatus.MEMBER_INFO_GET_SUCCESS, response);
	}
}
