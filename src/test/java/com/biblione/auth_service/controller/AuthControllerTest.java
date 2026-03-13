package com.biblione.auth_service.controller;

import com.biblione.auth_service.config.SecurityConfig;
import com.biblione.auth_service.dto.request.LoginRequest;
import com.biblione.auth_service.dto.request.RefreshTokenRequest;
import com.biblione.auth_service.dto.request.RegisterRequest;
import com.biblione.auth_service.dto.response.AuthResponse;
import com.biblione.auth_service.dto.response.UserResponse;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.*;
import com.biblione.auth_service.security.jwt.JwtAuthenticationFilter;
import com.biblione.auth_service.security.oauth.OAuth2AuthenticationFailureHandler;
import com.biblione.auth_service.security.oauth.OAuth2AuthenticationSuccessHandler;
import com.biblione.auth_service.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        value = AuthController.class,
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = SecurityConfig.class
        )
)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockitoBean AuthService authService;

    // Mocks necessários para satisfazer o contexto de segurança excluído
    @MockitoBean JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockitoBean OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
    @MockitoBean OAuth2AuthenticationFailureHandler oauth2FailureHandler;

    private static final String BASE_URL = "/api/v1/auth";

    // ─── helpers ─────────────────────────────────────────────────────────────

    private AuthResponse buildAuthResponse() {
        return AuthResponse.builder()
                .accessToken("access.token.ok")
                .refreshToken(UUID.randomUUID().toString())
                .expiresIn(86400L)
                .user(UserResponse.builder()
                        .id(UUID.randomUUID())
                        .name("João Silva")
                        .email("joao@biblione.com")
                        .role(UserRole.READER)
                        .createdAt(OffsetDateTime.now())
                        .build())
                .build();
    }

    // ─── POST /register ───────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /register: corpo válido → 201 Created com AuthResponse")
    void register_validBody_returns201() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("João Silva");
        body.setEmail("joao@biblione.com");
        body.setPassword("senha@1234");

        when(authService.register(any(), any())).thenReturn(buildAuthResponse());

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value("access.token.ok"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value("joao@biblione.com"));
    }

    @Test
    @DisplayName("POST /register: nome em branco → 400 Bad Request")
    void register_blankName_returns400() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("");
        body.setEmail("joao@biblione.com");
        body.setPassword("senha@1234");

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /register: e-mail inválido → 400 Bad Request")
    void register_invalidEmail_returns400() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("João Silva");
        body.setEmail("nao-e-um-email");
        body.setPassword("senha@1234");

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /register: senha curta (< 8 chars) → 400 Bad Request")
    void register_shortPassword_returns400() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("João Silva");
        body.setEmail("joao@biblione.com");
        body.setPassword("curta");

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /register: e-mail já cadastrado → 409 Conflict")
    void register_duplicateEmail_returns409() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("João Silva");
        body.setEmail("joao@biblione.com");
        body.setPassword("senha@1234");

        when(authService.register(any(), any()))
                .thenThrow(new UserAlreadyExistsException("joao@biblione.com"));

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("POST /register: domínio não permitido → 400 Bad Request")
    void register_invalidDomain_returns400() throws Exception {
        RegisterRequest body = new RegisterRequest();
        body.setName("Externo");
        body.setEmail("externo@gmail.com");
        body.setPassword("senha@1234");

        when(authService.register(any(), any()))
                .thenThrow(new InvalidEmailDomainException("biblione.com"));

        mockMvc.perform(post(BASE_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    // ─── POST /login ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /login: credenciais válidas → 200 OK com AuthResponse")
    void login_validCredentials_returns200() throws Exception {
        LoginRequest body = new LoginRequest();
        body.setEmail("joao@biblione.com");
        body.setPassword("senha@1234");

        when(authService.login(any(), any())).thenReturn(buildAuthResponse());

        mockMvc.perform(post(BASE_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access.token.ok"))
                .andExpect(jsonPath("$.user.role").value("READER"));
    }

    @Test
    @DisplayName("POST /login: e-mail inválido → 400 Bad Request")
    void login_invalidEmail_returns400() throws Exception {
        LoginRequest body = new LoginRequest();
        body.setEmail("invalido");
        body.setPassword("senha@1234");

        mockMvc.perform(post(BASE_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /login: senha vazia → 400 Bad Request")
    void login_blankPassword_returns400() throws Exception {
        LoginRequest body = new LoginRequest();
        body.setEmail("joao@biblione.com");
        body.setPassword("");

        mockMvc.perform(post(BASE_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /login: credenciais inválidas → 401 Unauthorized")
    void login_invalidCredentials_returns401() throws Exception {
        LoginRequest body = new LoginRequest();
        body.setEmail("joao@biblione.com");
        body.setPassword("senhaErrada");

        when(authService.login(any(), any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post(BASE_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /login: usuário inativo → 403 Forbidden")
    void login_inactiveUser_returns403() throws Exception {
        LoginRequest body = new LoginRequest();
        body.setEmail("inativo@biblione.com");
        body.setPassword("senha@1234");

        when(authService.login(any(), any())).thenThrow(new UserInactiveException());

        mockMvc.perform(post(BASE_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isForbidden());
    }

    // ─── POST /refresh ────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /refresh: refresh token válido → 200 OK com novo AuthResponse")
    void refresh_validToken_returns200() throws Exception {
        RefreshTokenRequest body = new RefreshTokenRequest();
        body.setRefreshToken(UUID.randomUUID().toString());

        when(authService.refresh(any(), any())).thenReturn(buildAuthResponse());

        mockMvc.perform(post(BASE_URL + "/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access.token.ok"));
    }

    @Test
    @DisplayName("POST /refresh: refresh token em branco → 400 Bad Request")
    void refresh_blankToken_returns400() throws Exception {
        RefreshTokenRequest body = new RefreshTokenRequest();
        body.setRefreshToken("  ");

        mockMvc.perform(post(BASE_URL + "/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    @DisplayName("POST /refresh: token inválido ou expirado → 401 Unauthorized")
    void refresh_invalidToken_returns401() throws Exception {
        RefreshTokenRequest body = new RefreshTokenRequest();
        body.setRefreshToken("token-invalido");

        when(authService.refresh(any(), any())).thenThrow(new InvalidTokenException());

        mockMvc.perform(post(BASE_URL + "/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isUnauthorized());
    }

    // ─── POST /logout ─────────────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "550e8400-e29b-41d4-a716-446655440000", roles = "READER")
    @DisplayName("POST /logout: usuário autenticado → 204 No Content")
    void logout_authenticatedUser_returns204() throws Exception {
        doNothing().when(authService).logout(any(), any());

        mockMvc.perform(post(BASE_URL + "/logout").with(csrf()))
                .andExpect(status().isNoContent());

        verify(authService).logout(eq("550e8400-e29b-41d4-a716-446655440000"), any());
    }

    // ─── GET /validate ────────────────────────────────────────────────────────

    @Test
    @WithMockUser
    @DisplayName("GET /validate: token já validado pelo filtro → 200 OK")
    void validate_authenticatedRequest_returns200() throws Exception {
        mockMvc.perform(get(BASE_URL + "/validate"))
                .andExpect(status().isOk());
    }
}
