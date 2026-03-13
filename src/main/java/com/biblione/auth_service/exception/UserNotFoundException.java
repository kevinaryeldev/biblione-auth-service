package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends BusinessException {

  public UserNotFoundException() {
    super("E-mail ou senha inválidos.", HttpStatus.UNAUTHORIZED);
  }
}