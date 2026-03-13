package com.biblione.auth_service.exception;

import org.springframework.http.HttpStatus;

public class UserInactiveException extends BusinessException {

  public UserInactiveException() {
    super("Usuário inativo. Entre em contato com a biblioteca.", HttpStatus.FORBIDDEN);
  }
}