package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class InvalidEmailDomainException extends BusinessException {

    public InvalidEmailDomainException(String domain) {
        super("E-mail deve pertencer ao domínio: " + domain, HttpStatus.BAD_REQUEST);
    }
}