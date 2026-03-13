package com.biblione.auth_service.security.jwt;

import com.biblione.auth_service.exception.InvalidTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock private TokenService tokenService;
    @Mock private UserDetailsService userDetailsService;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void cleanUpSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    // ─── sem Authorization header ─────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: sem header Authorization → continua a cadeia sem autenticar")
    void doFilterInternal_noAuthorizationHeader_continuesChainUnauthenticated() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(tokenService, userDetailsService);
    }

    @Test
    @DisplayName("doFilterInternal: header sem prefixo 'Bearer ' → continua a cadeia sem autenticar")
    void doFilterInternal_nonBearerAuthHeader_continuesChainUnauthenticated() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(tokenService, userDetailsService);
    }

    // ─── token válido ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: Bearer token válido → popula o SecurityContext e continua a cadeia")
    void doFilterInternal_validBearerToken_setsAuthenticationAndContinues() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = "valid.jwt.token";

        UserDetails userDetails = User.builder()
                .username(userId.toString())
                .password("")
                .authorities(List.of())
                .build();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenService.extractUserId(token)).thenReturn(userId);
        when(userDetailsService.loadUserByUsername(userId.toString())).thenReturn(userDetails);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                .isEqualTo(userId.toString());
    }

    @Test
    @DisplayName("doFilterInternal: contexto já autenticado → não recarrega UserDetails")
    void doFilterInternal_alreadyAuthenticated_doesNotReloadUserDetails() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = "valid.jwt.token";

        UserDetails userDetails = User.builder()
                .username(userId.toString())
                .password("")
                .authorities(List.of())
                .build();

        // Popula o contexto manualmente antes de chamar o filtro
        filter.doFilterInternal(request, response, filterChain);    // first call — no header, context empty

        // Reseta e prepara um contexto já populado
        SecurityContextHolder.clearContext();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenService.extractUserId(token)).thenReturn(userId);
        when(userDetailsService.loadUserByUsername(userId.toString())).thenReturn(userDetails);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        // Deve ter chamado loadUserByUsername apenas uma vez (na segunda chamada)
        verify(userDetailsService, times(1)).loadUserByUsername(userId.toString());
    }

    // ─── token inválido ───────────────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: token JWT inválido → continua a cadeia sem autenticar")
    void doFilterInternal_invalidToken_continuesChainUnauthenticated() throws Exception {
        String token = "invalid.jwt.token";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenService.extractUserId(token)).thenThrow(new InvalidTokenException());

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(userDetailsService);
    }

    @Test
    @DisplayName("doFilterInternal: exceção genérica ao extrair userId → continua a cadeia sem autenticar")
    void doFilterInternal_unexpectedExceptionDuringTokenParsing_continuesChainUnauthenticated() throws Exception {
        String token = "qualquer.token";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenService.extractUserId(token)).thenThrow(new RuntimeException("Erro inesperado"));

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
