package com.biblione.auth_service.security;

import com.biblione.auth_service.entity.User;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.InvalidCredentialsException;
import com.biblione.auth_service.exception.UserInactiveException;
import com.biblione.auth_service.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    // ─── loadUserByUsername ───────────────────────────────────────────────────

    @Test
    @DisplayName("loadUserByUsername: usuário ativo → retorna UserDetails com username = userId e role correta")
    void loadUserByUsername_activeUser_returnsCorrectUserDetails() {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("ana@biblione.com")
                .passwordHash("$2a$10$hashed")
                .role(UserRole.READER)
                .active(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        UserDetails details = userDetailsService.loadUserByUsername(userId.toString());

        assertThat(details.getUsername()).isEqualTo(userId.toString());
        assertThat(details.getPassword()).isEqualTo(user.getPasswordHash());
        assertThat(details.getAuthorities())
                .extracting("authority")
                .containsExactly("ROLE_READER");
    }

    @Test
    @DisplayName("loadUserByUsername: administrador ativo → retorna authority ROLE_ADMIN")
    void loadUserByUsername_adminUser_returnsAdminAuthority() {
        UUID userId = UUID.randomUUID();
        User admin = User.builder()
                .id(userId)
                .email("admin@biblione.com")
                .passwordHash("$2a$10$hashed")
                .role(UserRole.ADMIN)
                .active(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(admin));

        UserDetails details = userDetailsService.loadUserByUsername(userId.toString());

        assertThat(details.getAuthorities())
                .extracting("authority")
                .containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("loadUserByUsername: ID inexistente → lança InvalidCredentialsException")
    void loadUserByUsername_userNotFound_throwsInvalidCredentialsException() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername(userId.toString()))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    @DisplayName("loadUserByUsername: usuário inativo → lança UserInactiveException")
    void loadUserByUsername_inactiveUser_throwsUserInactiveException() {
        UUID userId = UUID.randomUUID();
        User inactiveUser = User.builder()
                .id(userId)
                .email("inativo@biblione.com")
                .role(UserRole.READER)
                .active(false)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(inactiveUser));

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername(userId.toString()))
                .isInstanceOf(UserInactiveException.class);
    }

    @Test
    @DisplayName("loadUserByUsername: usuário OAuth2 sem passwordHash → usa string vazia como password")
    void loadUserByUsername_oauth2UserWithNullPassword_usesEmptyString() {
        UUID userId = UUID.randomUUID();
        User oauthUser = User.builder()
                .id(userId)
                .email("oauth@biblione.com")
                .passwordHash(null) // usuário OAuth não tem senha local
                .role(UserRole.READER)
                .active(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(oauthUser));

        UserDetails details = userDetailsService.loadUserByUsername(userId.toString());

        assertThat(details.getPassword()).isEmpty();
    }
}
