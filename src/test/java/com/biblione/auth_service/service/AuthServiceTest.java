package com.biblione.auth_service.service;

import com.biblione.auth_service.dto.request.LoginRequest;
import com.biblione.auth_service.dto.request.RefreshTokenRequest;
import com.biblione.auth_service.dto.request.RegisterRequest;
import com.biblione.auth_service.dto.response.AuthResponse;
import com.biblione.auth_service.entity.RefreshToken;
import com.biblione.auth_service.entity.User;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.*;
import com.biblione.auth_service.repository.RefreshTokenRepository;
import com.biblione.auth_service.repository.UserRepository;
import com.biblione.auth_service.security.jwt.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private TokenService tokenService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private HttpServletRequest httpServletRequest;

    @InjectMocks
    private AuthService authService;

    private static final String ALLOWED_DOMAIN = "biblione.com";
    private static final long REFRESH_EXPIRATION_MS = 86_400_000L;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "allowedEmailDomain", ALLOWED_DOMAIN);
        ReflectionTestUtils.setField(authService, "refreshExpirationMs", REFRESH_EXPIRATION_MS);
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    private User buildActiveUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .name("João Silva")
                .email("joao@biblione.com")
                .passwordHash("$2a$10$hashedpassword")
                .role(UserRole.READER)
                .active(true)
                .build();
    }

    private void stubHttpRequest() {
        when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn(null);
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpServletRequest.getHeader("User-Agent")).thenReturn("JUnit-Test/1.0");
    }

    // ─── register ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("register: domínio válido e e-mail novo → retorna AuthResponse com tokens")
    void register_validRequest_returnsAuthResponse() {
        RegisterRequest request = new RegisterRequest();
        request.setName("João Silva");
        request.setEmail("joao@biblione.com");
        request.setPassword("senha@1234");

        User savedUser = buildActiveUser();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("$2a$10$hashed");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(tokenService.generateAccessToken(any(User.class))).thenReturn("access.token.ok");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(mock(RefreshToken.class));
        stubHttpRequest();

        AuthResponse response = authService.register(request, httpServletRequest);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("access.token.ok");
        assertThat(response.getRefreshToken()).isNotBlank();
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getUser().getEmail()).isEqualTo(savedUser.getEmail());

        verify(userRepository).save(any(User.class));
        verify(userRepository).flush();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("register: e-mail com domínio não permitido → lança InvalidEmailDomainException")
    void register_invalidEmailDomain_throwsInvalidEmailDomainException() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Externo");
        request.setEmail("externo@gmail.com");
        request.setPassword("senha@1234");

        assertThatThrownBy(() -> authService.register(request, httpServletRequest))
                .isInstanceOf(InvalidEmailDomainException.class)
                .hasMessageContaining(ALLOWED_DOMAIN);

        verifyNoInteractions(userRepository, passwordEncoder, tokenService, refreshTokenRepository);
    }

    @Test
    @DisplayName("register: e-mail já cadastrado → lança UserAlreadyExistsException")
    void register_emailAlreadyExists_throwsUserAlreadyExistsException() {
        RegisterRequest request = new RegisterRequest();
        request.setName("João Silva");
        request.setEmail("joao@biblione.com");
        request.setPassword("senha@1234");

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request, httpServletRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining(request.getEmail());

        verify(userRepository, never()).save(any());
    }

    // ─── login ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("login: credenciais corretas e usuário ativo → retorna AuthResponse")
    void login_validCredentials_returnsAuthResponse() {
        User user = buildActiveUser();

        LoginRequest request = new LoginRequest();
        request.setEmail(user.getEmail());
        request.setPassword("senha@1234");

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash())).thenReturn(true);
        when(tokenService.generateAccessToken(user)).thenReturn("access.token.ok");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(mock(RefreshToken.class));
        stubHttpRequest();

        AuthResponse response = authService.login(request, httpServletRequest);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("access.token.ok");
        assertThat(response.getUser().getEmail()).isEqualTo(user.getEmail());
    }

    @Test
    @DisplayName("login: e-mail não cadastrado → lança InvalidCredentialsException")
    void login_emailNotFound_throwsInvalidCredentialsException() {
        LoginRequest request = new LoginRequest();
        request.setEmail("naoexiste@biblione.com");
        request.setPassword("senha@1234");

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request, httpServletRequest))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    @DisplayName("login: usuário inativo → lança UserInactiveException sem verificar senha")
    void login_inactiveUser_throwsUserInactiveException() {
        User inactiveUser = buildActiveUser();
        inactiveUser.setActive(false);

        LoginRequest request = new LoginRequest();
        request.setEmail(inactiveUser.getEmail());
        request.setPassword("senha@1234");

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(inactiveUser));

        assertThatThrownBy(() -> authService.login(request, httpServletRequest))
                .isInstanceOf(UserInactiveException.class);

        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    @DisplayName("login: senha incorreta → lança InvalidCredentialsException")
    void login_wrongPassword_throwsInvalidCredentialsException() {
        User user = buildActiveUser();

        LoginRequest request = new LoginRequest();
        request.setEmail(user.getEmail());
        request.setPassword("senhaErrada");

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request, httpServletRequest))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    // ─── refresh ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("refresh: token válido → revoga o antigo e retorna novo AuthResponse")
    void refresh_validToken_revokesPreviousAndReturnsNewAuthResponse() {
        User user = buildActiveUser();
        String rawToken = UUID.randomUUID().toString();

        RefreshToken validToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash("qualquer-hash")
                .expiresAt(OffsetDateTime.now().plusDays(1))
                .build();

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken(rawToken);

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(validToken));
        when(tokenService.generateAccessToken(user)).thenReturn("new.access.token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(mock(RefreshToken.class));
        stubHttpRequest();

        AuthResponse response = authService.refresh(request, httpServletRequest);

        assertThat(response.getAccessToken()).isEqualTo("new.access.token");
        assertThat(validToken.getRevokedAt()).isNotNull();
        // 1ª chamada: revoga o token atual; 2ª: salva o novo refresh token
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("refresh: token não encontrado → lança InvalidTokenException")
    void refresh_tokenNotFound_throwsInvalidTokenException() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("token-inexistente");

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh(request, httpServletRequest))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("refresh: token já revogado → lança InvalidTokenException")
    void refresh_revokedToken_throwsInvalidTokenException() {
        User user = buildActiveUser();
        RefreshToken revokedToken = RefreshToken.builder()
                .user(user)
                .tokenHash("qualquer-hash")
                .expiresAt(OffsetDateTime.now().plusDays(1))
                .revokedAt(OffsetDateTime.now().minusHours(1))
                .build();

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("token-revogado");

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> authService.refresh(request, httpServletRequest))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("refresh: token expirado → lança InvalidTokenException")
    void refresh_expiredToken_throwsInvalidTokenException() {
        User user = buildActiveUser();
        RefreshToken expiredToken = RefreshToken.builder()
                .user(user)
                .tokenHash("qualquer-hash")
                .expiresAt(OffsetDateTime.now().minusDays(1))
                .build();

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("token-expirado");

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> authService.refresh(request, httpServletRequest))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("refresh: usuário inativo → lança UserInactiveException")
    void refresh_inactiveUser_throwsUserInactiveException() {
        User inactiveUser = buildActiveUser();
        inactiveUser.setActive(false);

        RefreshToken validToken = RefreshToken.builder()
                .user(inactiveUser)
                .tokenHash("qualquer-hash")
                .expiresAt(OffsetDateTime.now().plusDays(1))
                .build();

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("token-valido");

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(validToken));

        assertThatThrownBy(() -> authService.refresh(request, httpServletRequest))
                .isInstanceOf(UserInactiveException.class);
    }

    // ─── logout ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("logout: invoca revogação de todos os tokens do usuário")
    void logout_revokesAllUserTokens() {
        UUID userId = UUID.randomUUID();
        doNothing().when(refreshTokenRepository).revokeAllByUserId(userId);

        authService.logout(userId.toString(), httpServletRequest);

        verify(refreshTokenRepository).revokeAllByUserId(userId);
    }
}
