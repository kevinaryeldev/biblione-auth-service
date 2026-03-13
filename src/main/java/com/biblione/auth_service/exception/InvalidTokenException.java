package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class InvalidTokenException extends BusinessException {

    public InvalidTokenException() {
        super("Token inválido ou expirado.", HttpStatus.UNAUTHORIZED);
    }
}