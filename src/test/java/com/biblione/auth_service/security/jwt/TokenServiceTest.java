package com.biblione.auth_service.security.jwt;

import com.biblione.auth_service.entity.User;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

class TokenServiceTest {

    // Mínimo de 32 bytes para HMAC-SHA256
    private static final String SECRET =
            "biblione-super-secret-key-para-testes-unitarios-jwt!!";
    private static final long EXPIRATION_MS = 900_000L; // 15 min

    private TokenService tokenService;
    private User user;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(SECRET, EXPIRATION_MS);

        user = User.builder()
                .id(UUID.randomUUID())
                .name("Ana Costa")
                .email("ana@biblione.com")
                .role(UserRole.READER)
                .active(true)
                .build();
    }

    // ─── generateAccessToken ─────────────────────────────────────────────────

    @Test
    @DisplayName("generateAccessToken: retorna string JWT não vazia")
    void generateAccessToken_returnsNonBlankJwt() {
        String token = tokenService.generateAccessToken(user);

        assertThat(token)
                .isNotBlank()
                .contains(".");          // formato header.payload.signature
    }

    @Test
    @DisplayName("generateAccessToken: token contém as claims corretas")
    void generateAccessToken_tokenContainsExpectedClaims() {
        String token = tokenService.generateAccessToken(user);
        Claims claims = tokenService.validateAndExtractClaims(token);

        assertThat(claims.getSubject()).isEqualTo(user.getId().toString());
        assertThat(claims.get("email", String.class)).isEqualTo(user.getEmail());
        assertThat(claims.get("role", String.class)).isEqualTo(user.getRole().name());
        assertThat(claims.get("name", String.class)).isEqualTo(user.getName());
    }

    // ─── validateAndExtractClaims ────────────────────────────────────────────

    @Test
    @DisplayName("validateAndExtractClaims: token válido → retorna Claims")
    void validateAndExtractClaims_validToken_returnsClaims() {
        String token = tokenService.generateAccessToken(user);

        Claims claims = tokenService.validateAndExtractClaims(token);

        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo(user.getId().toString());
    }

    @Test
    @DisplayName("validateAndExtractClaims: token malformado → lança InvalidTokenException")
    void validateAndExtractClaims_malformedToken_throwsInvalidTokenException() {
        assertThatThrownBy(() -> tokenService.validateAndExtractClaims("token.invalido.qualquer"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("validateAndExtractClaims: token assinado com chave diferente → lança InvalidTokenException")
    void validateAndExtractClaims_wrongSignature_throwsInvalidTokenException() {
        TokenService otherService = new TokenService(
                "outra-chave-secreta-totalmente-diferente-para-teste!!", EXPIRATION_MS);

        String tokenDeOutraChave = otherService.generateAccessToken(user);

        assertThatThrownBy(() -> tokenService.validateAndExtractClaims(tokenDeOutraChave))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("validateAndExtractClaims: token expirado → lança InvalidTokenException")
    void validateAndExtractClaims_expiredToken_throwsInvalidTokenException() {
        TokenService expiredService = new TokenService(SECRET, -1000L);
        String expiredToken = expiredService.generateAccessToken(user);

        assertThatThrownBy(() -> tokenService.validateAndExtractClaims(expiredToken))
                .isInstanceOf(InvalidTokenException.class);
    }

    // ─── extractUserId ───────────────────────────────────────────────────────

    @Test
    @DisplayName("extractUserId: token válido → retorna UUID do usuário")
    void extractUserId_validToken_returnsCorrectUUID() {
        String token = tokenService.generateAccessToken(user);

        UUID extractedId = tokenService.extractUserId(token);

        assertThat(extractedId).isEqualTo(user.getId());
    }

    @Test
    @DisplayName("extractUserId: token inválido → lança InvalidTokenException")
    void extractUserId_invalidToken_throwsInvalidTokenException() {
        assertThatThrownBy(() -> tokenService.extractUserId("token.invalido"))
                .isInstanceOf(InvalidTokenException.class);
    }

    // ─── isTokenValid ────────────────────────────────────────────────────────

    @Test
    @DisplayName("isTokenValid: token correto → retorna true")
    void isTokenValid_validToken_returnsTrue() {
        String token = tokenService.generateAccessToken(user);

        assertThat(tokenService.isTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("isTokenValid: token malformado → retorna false")
    void isTokenValid_malformedToken_returnsFalse() {
        assertThat(tokenService.isTokenValid("isso.nao.e.um.jwt")).isFalse();
    }

    @Test
    @DisplayName("isTokenValid: token expirado → retorna false")
    void isTokenValid_expiredToken_returnsFalse() {
        TokenService shortLived = new TokenService(SECRET, -1000L);
        String expiredToken = shortLived.generateAccessToken(user);

        assertThat(tokenService.isTokenValid(expiredToken)).isFalse();
    }

    @Test
    @DisplayName("isTokenValid: string vazia → retorna false")
    void isTokenValid_emptyString_returnsFalse() {
        assertThat(tokenService.isTokenValid("")).isFalse();
    }
}
