package com.biblione.auth_service.service;

import com.biblione.auth_service.dto.request.LoginRequest;
import com.biblione.auth_service.dto.request.RegisterRequest;
import com.biblione.auth_service.dto.request.RefreshTokenRequest;
import com.biblione.auth_service.dto.response.AuthResponse;
import com.biblione.auth_service.dto.response.UserResponse;
import com.biblione.auth_service.entity.RefreshToken;
import com.biblione.auth_service.entity.User;
import com.biblione.auth_service.enums.UserRole;
import com.biblione.auth_service.exception.*;
import com.biblione.auth_service.repository.RefreshTokenRepository;
import com.biblione.auth_service.repository.UserRepository;
import com.biblione.auth_service.security.jwt.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.OffsetDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Value("${biblione.jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    @Value("${biblione.auth.allowed-email-domain}")
    private String allowedEmailDomain;

    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        validateEmailDomain(request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException(request.getEmail());
        }

        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.READER)
                .active(true)
                .build();

        userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        return buildAuthResponse(user, httpRequest);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(InvalidCredentialsException::new);

        if (!user.isActive()) {
            throw new UserInactiveException();
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        log.info("User logged in: {}", user.getEmail());
        return buildAuthResponse(user, httpRequest);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        String tokenHash = hashToken(request.getRefreshToken());

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(InvalidTokenException::new);

        if (!refreshToken.isValid()) {
            throw new InvalidTokenException();
        }

        User user = refreshToken.getUser();

        if (!user.isActive()) {
            throw new UserInactiveException();
        }

        // revoga o token atual e gera um novo
        refreshToken.setRevokedAt(OffsetDateTime.now());
        refreshTokenRepository.save(refreshToken);

        log.info("Token refreshed for user: {}", user.getEmail());
        return buildAuthResponse(user, httpRequest);
    }

    @Transactional
    public void logout(String userId, HttpServletRequest httpRequest) {
        refreshTokenRepository.revokeAllByUserId(UUID.fromString(userId));
        log.info("User logged out: {}", userId);
    }

    private AuthResponse buildAuthResponse(User user, HttpServletRequest httpRequest) {
        String accessToken = tokenService.generateAccessToken(user);
        String rawRefreshToken = UUID.randomUUID().toString();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(hashToken(rawRefreshToken))
                .expiresAt(OffsetDateTime.now().plusNanos(refreshExpirationMs * 1_000_000))
                .ipAddress(resolveIpAddress(httpRequest))
                .userAgent(httpRequest.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .expiresIn(refreshExpirationMs / 1000)
                .user(toUserResponse(user))
                .build();
    }

    private void validateEmailDomain(String email) {
        if (!email.endsWith("@" + allowedEmailDomain)) {
            throw new InvalidEmailDomainException(allowedEmailDomain);
        }
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

    private InetAddress resolveIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .build();
    }
}