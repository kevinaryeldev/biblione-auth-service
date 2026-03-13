package com.biblione.auth_service.security.oauth;

import com.biblione.auth_service.entity.User;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.InvalidEmailDomainException;
import com.biblione.auth_service.repository.RefreshTokenRepository;
import com.biblione.auth_service.repository.UserRepository;
import com.biblione.auth_service.security.jwt.TokenService;
import com.biblione.auth_service.entity.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;

    @Value("${biblione.auth.allowed-email-domain}")
    private String allowedEmailDomain;

    @Value("${biblione.jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    @Value("${biblione.oauth2.redirect-uri}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String sub = oauth2User.getAttribute("sub");

        if (!email.endsWith("@" + allowedEmailDomain)) {
            throw new InvalidEmailDomainException(allowedEmailDomain);
        }

        User user = userRepository.findByOauthProviderAndOauthSub("google", sub)
                .orElseGet(() -> createUser(email, name, sub));

        if (!user.isActive()) {
            response.sendRedirect(redirectUri + "?error=inactive");
            return;
        }

        String accessToken = tokenService.generateAccessToken(user);
        String rawRefreshToken = UUID.randomUUID().toString();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(hashToken(rawRefreshToken))
                .expiresAt(OffsetDateTime.now().plusNanos(refreshExpirationMs * 1_000_000))
                .ipAddress(null)
                .userAgent(request.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(refreshToken);

        log.info("OAuth2 login successful for user: {}", email);
        getRedirectStrategy().sendRedirect(request, response,
                redirectUri + "?token=" + accessToken + "&refreshToken=" + rawRefreshToken);
    }

    private User createUser(String email, String name, String sub) {
        User user = User.builder()
                .name(name)
                .email(email)
                .oauthProvider("google")
                .oauthSub(sub)
                .role(UserRole.READER)
                .active(true)
                .build();
        return userRepository.save(user);
    }

    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing token", e);
        }
    }
}