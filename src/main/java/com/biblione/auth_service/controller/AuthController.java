package com.biblione.auth_service.controller;

import com.biblione.auth_service.dto.request.LoginRequest;
import com.biblione.auth_service.dto.request.RefreshTokenRequest;
import com.biblione.auth_service.dto.request.RegisterRequest;
import com.biblione.auth_service.dto.response.AuthResponse;
import com.biblione.auth_service.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints de autenticação")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "Registra um novo usuário")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(authService.register(request, httpRequest));
    }

    @PostMapping("/login")
    @Operation(summary = "Realiza login com email e senha")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, httpRequest));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renova o access token")
    public ResponseEntity<AuthResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.refresh(request, httpRequest));
    }

    @PostMapping("/logout")
    @Operation(summary = "Realiza logout revogando todos os tokens ativos")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        authService.logout(userDetails.getUsername(), httpRequest);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/validate")
    @Operation(summary = "Valida o token JWT — uso interno entre serviços")
    public ResponseEntity<Void> validate() {
        // se chegou aqui, o JwtAuthenticationFilter já validou o token
        return ResponseEntity.ok().build();
    }
}