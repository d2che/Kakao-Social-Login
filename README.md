# 카카오 소셜 로그인 구현 프로젝트 (Spring Boot + OAuth2 + JWT)

## 프로젝트 개요

이 프로젝트는 **Spring Boot 3.5.7**, **Spring Security OAuth2**, **JWT**를 활용하여 카카오 소셜 로그인을 구현한 템플릿 프로젝트입니다. 카카오 OAuth2 인증 플로우부터 JWT 토큰 발급 및 갱신까지 전체 소셜 로그인 프로세스를 학습하고 적용할 수 있도록 구성되어 있습니다.

## 주요 기능

- **카카오 OAuth2 로그인**: 카카오 계정으로 간편 로그인
- **JWT 기반 인증**: Access Token과 Refresh Token을 사용한 Stateless 인증
- **토큰 자동 재발급**: Refresh Token을 활용한 Access Token 자동 갱신
- **사용자 정보 관리**: 소셜 로그인 사용자 정보 자동 저장 및 업데이트
- **H2 인메모리 DB**: 빠른 테스트를 위한 H2 데이터베이스 사용
- **Swagger UI**: API 문서화 및 테스트 지원

## 기술 스택

### Backend
- **Java 17**
- **Spring Boot 3.5.7**
- **Spring Security**
- **Spring OAuth2 Client**
- **Spring Data JPA**

### Authentication & Authorization
- **OAuth2**: 카카오 소셜 로그인
- **JWT (JJWT 0.11.5)**: 토큰 기반 인증

### Database
- **H2 Database**: 개발 및 테스트용 인메모리 DB

### API Documentation
- **Swagger UI (SpringDoc OpenAPI 2.8.9)**

### Build Tool
- **Gradle**

## 프로젝트 구조

```
src/main/java/hufs/backend/hufslion_sso_session/
│
├── common/
│   ├── advice/
│   │   └── GlobalExceptionAdvice.java          # 전역 예외 처리
│   │
│   ├── entity/
│   │   ├── BaseTimeEntity.java                 # 생성/수정 시간 자동 관리
│   │   └── ExtendBaseTimeEntity.java           # 소프트 삭제 지원
│   │
│   ├── exception/                              # 커스텀 예외 클래스들
│   │   ├── BaseException.java
│   │   ├── BadRequestException.java
│   │   ├── UnauthorizedException.java
│   │   ├── ForbiddenException.java
│   │   ├── NotFoundException.java
│   │   ├── ConflictException.java
│   │   ├── InternalServerException.java
│   │   └── ServiceUnavailableException.java
│   │
│   ├── oauth2/                                 # OAuth2 관련 핵심 로직
│   │   ├── OAuth2UserService.java              # OAuth2 사용자 정보 처리
│   │   ├── OAuthAttributes.java                # 소셜 로그인 사용자 정보 파싱
│   │   ├── OAuth2AuthenticationSuccessHandler.java  # 로그인 성공 처리
│   │   ├── OAuth2AuthenticationFailureHandler.java  # 로그인 실패 처리
│   │   └── MemberDTO.java                      # 세션용 사용자 DTO
│   │
│   ├── response/
│   │   ├── ApiResponse.java                    # 통일된 API 응답 형식
│   │   ├── SuccessStatus.java                  # 성공 응답 상태 코드
│   │   └── ErrorStatus.java                    # 에러 응답 상태 코드
│   │
│   └── security/                               # Spring Security 설정
│       ├── SecurityConfig.java                 # 보안 설정 (핵심)
│       ├── CustomUserDetailsService.java       # 사용자 조회 서비스
│       └── entity/
│           └── SecurityMember.java             # Spring Security용 사용자 객체
│
├── member/                                     # 회원 관련 도메인
│   ├── controller/
│   │   └── MemberController.java               # 회원 관련 API
│   │
│   ├── entity/
│   │   ├── Member.java                         # 회원 엔티티
│   │   ├── Role.java                           # 권한 Enum
│   │   └── Type.java                           # 회원 타입 Enum
│   │
│   ├── repository/
│   │   └── MemberRepository.java               # 회원 DB 접근
│   │
│   └── jwt/                                    # JWT 관련 기능
│       ├── entity/
│       │   └── RefreshToken.java               # Refresh Token 엔티티
│       │
│       ├── filter/
│       │   ├── JwtAuthenticationProcessingFilter.java  # JWT 인증 필터
│       │   └── FilterExceptionHandler.java     # 필터 예외 처리
│       │
│       ├── repository/
│       │   └── RefreshTokenRepository.java     # Refresh Token DB 접근
│       │
│       └── service/
│           ├── JwtService.java                 # JWT 토큰 생성/검증
│           └── RefreshTokenService.java        # Refresh Token 관리
│
└── HufslionSsoSessionApplication.java          # 메인 애플리케이션
```

## 시작하기

### 1. 카카오 개발자 센터 설정

카카오 소셜 로그인을 사용하기 위해서는 먼저 카카오 개발자 센터에서 애플리케이션을 등록해야 합니다.

#### 1-1. 카카오 개발자 센터 접속
1. [카카오 개발자 센터](https://developers.kakao.com/)에 접속합니다.
2. 카카오 계정으로 로그인합니다.

#### 1-2. 애플리케이션 추가
1. 상단 메뉴에서 **내 애플리케이션**을 클릭합니다.
2. **애플리케이션 추가하기** 버튼을 클릭합니다.
3. 앱 이름, 사업자명을 입력하고 저장합니다.

#### 1-3. REST API 키 확인
1. 생성된 애플리케이션을 클릭합니다.
2. **앱 키** 탭에서 **REST API 키**를 확인하고 복사합니다.
   - 이 키는 `application.yml`의 `client-id`에 입력됩니다.

#### 1-4. 카카오 로그인 활성화
1. 좌측 메뉴에서 **제품 설정 > 카카오 로그인**을 클릭합니다.
2. **활성화 설정**의 상태를 **ON**으로 변경합니다.

#### 1-5. Redirect URI 설정
1. **카카오 로그인** 페이지에서 **Redirect URI**를 등록합니다.
2. **Redirect URI 등록하기**를 클릭하고 다음을 입력합니다:
   ```
   http://localhost:8080/login/oauth2/code/kakao
   ```
3. 저장 버튼을 클릭합니다.

#### 1-6. 동의 항목 설정
1. 좌측 메뉴에서 **제품 설정 > 카카오 로그인 > 동의항목**을 클릭합니다.
2. 다음 항목들을 설정합니다:
   - **닉네임**: 필수 동의 또는 선택 동의로 설정
   - **카카오계정(이메일)**: 필수 동의 또는 선택 동의로 설정
3. 각 항목의 **설정** 버튼을 클릭하여 활성화합니다.

#### 1-7. Client Secret 발급 (선택)
1. 좌측 메뉴에서 **제품 설정 > 카카오 로그인 > 보안**을 클릭합니다.
2. **Client Secret** 섹션에서 **코드 생성** 버튼을 클릭합니다.
3. 생성된 **Client Secret** 키를 복사합니다.
   - 이 키는 `application.yml`의 `client-secret`에 입력됩니다.
4. **활성화** 상태를 **ON**으로 변경합니다.

### 2. 프로젝트 설정

#### 2-1. 프로젝트 클론
```bash
git clone [repository-url]
cd hufslion_sso_session_template
```

#### 2-2. application.yml 설정
`src/main/resources/application.yml` 파일을 열어 카카오 앱 정보를 입력합니다.

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          kakao:
            client-id: {카카오 REST API 키}
            client-secret: {카카오 Client Secret}
            redirect-uri: "http://localhost:8080/login/oauth2/code/kakao"
            authorization-grant-type: authorization_code
            client-name: Kakao
            scope:
              - profile_nickname
              - account_email
            client-authentication-method: client_secret_post
        provider:
          kakao:
            authorization-uri: https://kauth.kakao.com/oauth/authorize
            token-uri: https://kauth.kakao.com/oauth/token
            user-info-uri: https://kapi.kakao.com/v2/user/me
            user-name-attribute: id

jwt:
  access:
    header: Authorization
    expiration: 3600000     # 1시간
  refresh:
    header: X-Refresh-Token
    expiration: 5259400000  # 2달
  secretKey: vTfT4bFjiaZWnjeikZXutfgX+LmLRB4iP5AN+FUWpTeqGDXgQbXDhYd9j5BA3DcDuyfGp+leNDtiJl2ilmxRjA==
```

**주의사항:**
- `client-id`와 `client-secret`은 카카오 개발자 센터에서 발급받은 값으로 교체해야 합니다.
- `jwt.secretKey`는 운영 환경에서는 환경 변수로 관리하는 것이 안전합니다.

#### 2-3. JWT Secret Key 생성 (선택사항)
보안을 위해 새로운 JWT Secret Key를 생성하려면 다음 코드를 실행하세요:

```java
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Base64;

public class SecretKeyGenerator {
    public static void main(String[] args) {
        String secretKey = Base64.getEncoder()
            .encodeToString(Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded());
        System.out.println("Generated Secret Key: " + secretKey);
    }
}
```

### 3. 실행 방법

#### 3-1. Gradle을 사용한 실행
```bash
./gradlew bootRun
```

#### 3-2. IDE에서 실행
- `HufslionSsoSessionApplication.java` 파일을 실행합니다.

#### 3-3. 실행 확인
애플리케이션이 성공적으로 시작되면 다음 URL들에 접속할 수 있습니다:

- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **H2 Console**: http://localhost:8080/h2-console
  - JDBC URL: `jdbc:h2:mem:testdb`
  - Username: `sa`
  - Password: (비워둠)

## 카카오 로그인 플로우

### 1. 로그인 시작
사용자가 다음 URL로 접속하면 카카오 로그인 페이지로 리다이렉트됩니다:
```
http://localhost:8080/oauth2/authorization/kakao
```

### 2. 카카오 인증 및 콜백
- 사용자가 카카오 계정으로 로그인하고 동의를 완료하면, 카카오는 설정된 Redirect URI로 인증 코드를 전달합니다.
- Spring Security가 자동으로 인증 코드를 Access Token으로 교환합니다.

### 3. 사용자 정보 처리 (OAuth2UserService)
`OAuth2UserService.java`에서 다음 작업을 수행합니다:

```java
public OAuth2User loadUser(OAuth2UserRequest userRequest) {
    // 1. 카카오로부터 사용자 정보를 가져옴
    OAuth2User oAuth2User = delegate.loadUser(userRequest);

    // 2. 카카오 응답 데이터를 파싱하여 OAuthAttributes 객체 생성
    OAuthAttributes attributes = OAuthAttributes.of("kakao", "id", oAuth2User.getAttributes());

    // 3. DB에 사용자 저장 또는 업데이트
    Member member = saveOrUpdate(attributes);

    // 4. 세션에 사용자 정보 저장
    httpSession.setAttribute("user", new MemberDTO(member));

    return new DefaultOAuth2User(...);
}
```

### 4. 로그인 성공 처리 (OAuth2AuthenticationSuccessHandler)
`OAuth2AuthenticationSuccessHandler.java`에서 JWT 토큰을 생성하고 프론트엔드로 리다이렉트합니다:

```java
public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
    Authentication authentication) {

    // 1. OAuth2User 정보에서 Member 조회
    Member member = memberRepository.findByOauthId(socialProvider + "_" + socialId)
        .orElseThrow(() -> new IllegalStateException("사용자를 찾을 수 없습니다."));

    // 2. JWT Access Token 및 Refresh Token 생성
    String accessToken = jwtService.createAccessToken(member);
    String refreshToken = jwtService.createRefreshToken(member.getId());

    // 3. 프론트엔드 URL로 토큰과 함께 리다이렉트
    String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000")
        .queryParam("token", accessToken)
        .queryParam("refresh", refreshToken)
        .build().toUriString();

    response.sendRedirect(targetUrl);
}
```

### 5. JWT 토큰 발급
- **Access Token**: 1시간 유효, API 요청 시 `Authorization` 헤더에 포함
- **Refresh Token**: 2개월 유효, DB에 저장되며 Access Token 갱신에 사용

## JWT 인증 플로우

### 1. API 요청 시 인증 (JwtAuthenticationProcessingFilter)
클라이언트가 API를 요청할 때 다음 과정을 거칩니다:

```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
    FilterChain filterChain) {

    // 1. Authorization 헤더에서 Access Token 추출
    Optional<String> accessTokenOpt = extractToken(request, accessTokenHeader)
        .filter(jwtService::isTokenValid);

    // 2. Access Token에서 이메일 추출 후 사용자 조회
    accessTokenOpt.ifPresent(token -> jwtService.extractEmail(token)
        .flatMap(memberRepository::findByEmail)
        .ifPresent(this::setAuthentication));  // SecurityContext에 인증 정보 설정

    // 3. 다음 필터로 진행
    filterChain.doFilter(request, response);
}
```

### 2. Access Token 재발급 (/api/v1/member/token-reissue)
Access Token이 만료되었을 때, Refresh Token으로 새로운 토큰을 발급받습니다:

**요청 예시:**
```http
GET /api/v1/member/token-reissue HTTP/1.1
Host: localhost:8080
X-Refresh-Token: Bearer {refresh_token}
```

**응답 예시:**
```json
{
  "code": 200,
  "message": "토큰 재발급 성공",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

## 주요 코드 설명

### 1. SecurityConfig.java
Spring Security의 전체 보안 설정을 담당합니다.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // 기본 로그인 폼 비활성화
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)

        // CSRF 비활성화 (JWT 사용으로 필요 없음)
        .csrf(AbstractHttpConfigurer::disable)

        // CORS 설정
        .cors(cors -> cors.configurationSource(request -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
            config.setAllowCredentials(true);
            config.setAllowedHeaders(Arrays.asList("Authorization", "X-Refresh-Token", "Content-Type"));
            return config;
        }))

        // Stateless 세션 정책 (JWT 사용)
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        // URL별 권한 설정
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/oauth2/authorization/**", "/login/oauth2/code/**").permitAll()
            .requestMatchers("/api/v1/member/**").permitAll()
            .anyRequest().authenticated()
        )

        // OAuth2 로그인 설정
        .oauth2Login(oauth2 -> oauth2
            .authorizationEndpoint(auth -> auth.baseUri("/oauth2/authorization"))
            .successHandler(oAuth2AuthenticationSuccessHandler)
            .failureHandler(oAuth2AuthenticationFailureHandler)
            .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
        );

    // JWT 필터 추가
    http.addFilterBefore(jwtAuthenticationProcessingFilter,
        UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```

**주요 설정:**
- `SessionCreationPolicy.STATELESS`: 세션을 사용하지 않고 JWT로 인증
- `oauth2Login()`: OAuth2 로그인 활성화
- `addFilterBefore()`: JWT 인증 필터를 UsernamePasswordAuthenticationFilter 전에 추가

### 2. OAuthAttributes.java
카카오, 네이버, 구글 등 다양한 OAuth2 제공자의 응답을 통일된 형태로 변환합니다.

```java
public static OAuthAttributes ofKakao(String registrationId, String userNameAttributeName,
    Map<String, Object> attributes) {

    // 카카오 응답 구조: attributes -> kakao_account -> profile
    Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
    Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

    return OAuthAttributes.builder()
        .name((String) profile.get("nickname"))              // 닉네임
        .email((String) kakaoAccount.get("email"))           // 이메일
        .profileImage((String) profile.get("profile_image_url"))  // 프로필 이미지
        .socialProvider(registrationId)                       // "kakao"
        .socialId(String.valueOf(attributes.get("id")))      // 카카오 회원번호
        .nameAttributeKey(userNameAttributeName)             // "id"
        .build();
}

public Member toEntity() {
    // OAuth ID 생성: "kakao_123456789" 형식
    String generatedUserId = socialProvider + "_" + socialId;

    return Member.builder()
        .oauthId(generatedUserId)
        .name(name)
        .email(email)
        .password("OAUTH_USER")  // OAuth 사용자는 비밀번호 불필요
        .build();
}
```

**카카오 응답 구조:**
```json
{
  "id": 123456789,
  "kakao_account": {
    "email": "user@example.com",
    "profile": {
      "nickname": "홍길동",
      "profile_image_url": "http://..."
    }
  }
}
```

### 3. JwtService.java
JWT 토큰의 생성, 검증, 정보 추출을 담당합니다.

```java
// Access Token 생성
public String createAccessToken(Member member) {
    Date now = new Date();
    Date expirationDate = new Date(now.getTime() + accessTokenExpirePeriod);

    return Jwts.builder()
        .setSubject(member.getId().toString())    // sub: 사용자 ID
        .claim("email", member.getEmail())        // 이메일
        .claim("type", "ACCESS")                  // 토큰 타입
        .setIssuedAt(now)                         // iat: 발급 시간
        .setExpiration(expirationDate)            // exp: 만료 시간
        .signWith(secretKey, SignatureAlgorithm.HS256)  // 서명
        .compact();
}

// 토큰 유효성 검증
public boolean isTokenValid(String token) {
    try {
        Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token);
        return true;
    } catch (ExpiredJwtException e) {
        log.warn("만료된 토큰입니다");
    } catch (JwtException e) {
        log.warn("유효하지 않은 토큰입니다");
    }
    return false;
}

// 토큰에서 이메일 추출
public Optional<String> extractEmail(String accessToken) {
    try {
        return Optional.ofNullable(
            getClaimsFromToken(accessToken).get("email", String.class)
        );
    } catch (Exception e) {
        log.error("토큰에서 이메일 추출 실패");
        return Optional.empty();
    }
}
```

### 4. Member.java (회원 엔티티)
소셜 로그인 사용자 정보를 저장하는 엔티티입니다.

```java
@Entity
@Table(name = "member")
@Getter
public class Member extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String email;  // 이메일 (유니크)

    @Column(nullable = true, length = 255)
    private String password;  // OAuth 사용자는 null

    @Column(nullable = true, unique = true, length = 100)
    private String oauthId;  // "kakao_123456789" 형식

    @Column(nullable = false, length = 10)
    private String name;  // 닉네임

    @Enumerated(EnumType.STRING)
    private Type type;  // 회원 타입

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    public Member update(String name) {
        this.name = name;
        return this;
    }
}
```

### 5. RefreshToken.java
Refresh Token을 DB에 저장하여 관리합니다.

```java
@Entity
@Table(name = "refresh_token")
@Getter
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 500)
    private String token;  // Refresh Token 값

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;  // 토큰 소유자

    @Column(nullable = false)
    private LocalDateTime expiresAt;  // 만료 시간

    @Column
    private LocalDateTime usedAt;  // 사용된 시간
}
```

## API 엔드포인트

### 1. 카카오 로그인 시작
```
GET /oauth2/authorization/kakao
```
카카오 로그인 페이지로 리다이렉트됩니다.

### 2. 카카오 로그인 콜백
```
GET /login/oauth2/code/kakao?code={authorization_code}
```
카카오로부터 인증 코드를 받아 자동으로 처리됩니다. (직접 호출 불필요)

### 3. Access Token 재발급
```http
GET /api/v1/member/token-reissue
X-Refresh-Token: Bearer {refresh_token}
```

**응답:**
```json
{
  "code": 200,
  "message": "토큰 재발급 성공",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

## 프론트엔드 연동 가이드

### 1. 로그인 버튼 구현
```javascript
// React 예시
const handleKakaoLogin = () => {
  window.location.href = 'http://localhost:8080/oauth2/authorization/kakao';
};

return (
  <button onClick={handleKakaoLogin}>
    카카오 로그인
  </button>
);
```

### 2. 콜백 처리 및 토큰 저장
```javascript
// React 예시 - 리다이렉트 URL: http://localhost:3000?token=xxx&refresh=yyy
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const accessToken = params.get('token');
  const refreshToken = params.get('refresh');

  if (accessToken && refreshToken) {
    // 로컬 스토리지에 저장
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);

    // URL에서 토큰 제거
    window.history.replaceState({}, document.title, '/');
  }
}, []);
```

### 3. API 요청 시 토큰 포함
```javascript
// Axios 예시
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8080/api',
});

// 요청 인터셉터: Access Token 자동 포함
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 응답 인터셉터: 토큰 만료 시 자동 재발급
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 401 에러이고, 토큰 재발급 요청이 아닌 경우
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refreshToken');

      try {
        // 토큰 재발급 요청
        const response = await axios.get(
          'http://localhost:8080/api/v1/member/token-reissue',
          {
            headers: {
              'X-Refresh-Token': `Bearer ${refreshToken}`
            }
          }
        );

        const { accessToken, refreshToken: newRefreshToken } = response.data.data;

        // 새 토큰 저장
        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('refreshToken', newRefreshToken);

        // 원래 요청 재시도
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh Token도 만료된 경우 로그아웃
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
```

### 4. 보호된 API 호출 예시
```javascript
// 사용자 정보 조회
const getUserInfo = async () => {
  try {
    const response = await api.get('/v1/member/me');
    console.log('사용자 정보:', response.data);
  } catch (error) {
    console.error('사용자 정보 조회 실패:', error);
  }
};
```

## 보안 고려사항

### 1. JWT Secret Key 관리
- **개발 환경**: `application.yml`에 하드코딩 가능
- **운영 환경**: 환경 변수로 관리 필수
  ```bash
  export JWT_SECRET_KEY=your-secret-key
  ```
  ```yaml
  jwt:
    secretKey: ${JWT_SECRET_KEY}
  ```

### 2. HTTPS 사용
운영 환경에서는 반드시 HTTPS를 사용하여 토큰이 암호화된 채널을 통해 전송되도록 해야 합니다.

### 3. Refresh Token 보안
- Refresh Token은 HttpOnly 쿠키에 저장하는 것이 더 안전합니다.
- 현재 구현은 학습 목적으로 간단하게 구성되어 있습니다.

### 4. CORS 설정
운영 환경에서는 허용할 도메인을 명확히 지정해야 합니다:
```java
config.setAllowedOrigins(Arrays.asList("https://yourdomain.com"));
```

### 5. Client Secret 노출 방지
`application.yml` 파일을 Git에 커밋할 때는 반드시 `.gitignore`에 추가하거나, 환경 변수로 관리하세요.

## 문제 해결 (Troubleshooting)

### 1. 카카오 로그인 후 리다이렉트가 안 됨
- 카카오 개발자 센터에서 Redirect URI 설정을 확인하세요.
- `application.yml`의 `redirect-uri`와 일치하는지 확인하세요.

### 2. 동의 항목 에러
- 카카오 개발자 센터의 **동의항목** 설정에서 `profile_nickname`과 `account_email`이 활성화되어 있는지 확인하세요.

### 3. JWT 토큰 검증 실패
- `application.yml`의 `jwt.secretKey`가 올바른지 확인하세요.
- Access Token의 만료 시간을 확인하세요.

### 4. H2 Console 접속 안 됨
- `application.yml`에서 `h2.console.enabled: true` 설정을 확인하세요.
- SecurityConfig에서 H2 Console 경로가 허용되어 있는지 확인하세요.

### 5. CORS 에러
- `SecurityConfig`의 CORS 설정에서 프론트엔드 URL이 포함되어 있는지 확인하세요.

## 참고 자료

- [Spring Security OAuth2 공식 문서](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
- [카카오 로그인 REST API 가이드](https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api)
- [JWT 공식 사이트](https://jwt.io/)
- [JJWT GitHub](https://github.com/jwtk/jjwt)

## 라이센스

이 프로젝트는 학습 목적으로 제작되었습니다.

## 기여

이슈 및 풀 리퀘스트는 언제든지 환영합니다.

---

**작성자**: HUFS LIKELION Backend Team
**최종 수정일**: 2025년