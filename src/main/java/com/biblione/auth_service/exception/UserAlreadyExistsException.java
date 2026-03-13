package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class UserAlreadyExistsException extends BusinessException {

    public UserAlreadyExistsException(String email) {
        super("E-mail já cadastrado: " + email, HttpStatus.CONFLICT);
    }
}