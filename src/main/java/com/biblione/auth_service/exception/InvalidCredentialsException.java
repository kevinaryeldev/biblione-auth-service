package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends BusinessException {

    public InvalidCredentialsException() {
        super("E-mail ou senha inválidos.", HttpStatus.UNAUTHORIZED);
    }
}