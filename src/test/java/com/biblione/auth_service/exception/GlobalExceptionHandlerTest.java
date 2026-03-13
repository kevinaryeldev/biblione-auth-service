package com.biblione.auth_service.exception;

import com.biblione.auth_service.dto.request.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        controllers = GlobalExceptionHandlerTest.FakeController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class}
)
@Import(GlobalExceptionHandler.class)
class GlobalExceptionHandlerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    /**
     * Controller auxiliar de testes — expõe endpoints que disparam cada tipo de exceção.
     */
    @RestController
    @RequestMapping("/test-handler")
    static class FakeController {

        @GetMapping("/user-already-exists")
        void throwUserAlreadyExists() {
            throw new UserAlreadyExistsException("test@biblione.com");
        }

        @GetMapping("/invalid-credentials")
        void throwInvalidCredentials() {
            throw new InvalidCredentialsException();
        }

        @GetMapping("/user-inactive")
        void throwUserInactive() {
            throw new UserInactiveException();
        }

        @GetMapping("/invalid-token")
        void throwInvalidToken() {
            throw new InvalidTokenException();
        }

        @GetMapping("/invalid-domain")
        void throwInvalidDomain() {
            throw new InvalidEmailDomainException("biblione.com");
        }

        @GetMapping("/generic-error")
        void throwGeneric() {
            throw new RuntimeException("Erro inesperado");
        }

        @PostMapping("/validation")
        void validated(@jakarta.validation.Valid @RequestBody RegisterRequest req) {
        }
    }

    // ─── BusinessException ────────────────────────────────────────────────────

    @Test
    @DisplayName("UserAlreadyExistsException → 409 Conflict com mensagem correta")
    void handleBusinessException_userAlreadyExists_returns409() throws Exception {
        mockMvc.perform(get("/test-handler/user-already-exists"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errors[0].detail", containsString("test@biblione.com")));
    }

    @Test
    @DisplayName("InvalidCredentialsException → 401 Unauthorized")
    void handleBusinessException_invalidCredentials_returns401() throws Exception {
        mockMvc.perform(get("/test-handler/invalid-credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0].detail").isNotEmpty());
    }

    @Test
    @DisplayName("UserInactiveException → 403 Forbidden")
    void handleBusinessException_userInactive_returns403() throws Exception {
        mockMvc.perform(get("/test-handler/user-inactive"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errors[0].detail").isNotEmpty());
    }

    @Test
    @DisplayName("InvalidTokenException → 401 Unauthorized")
    void handleBusinessException_invalidToken_returns401() throws Exception {
        mockMvc.perform(get("/test-handler/invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("InvalidEmailDomainException → 400 Bad Request com domínio na mensagem")
    void handleBusinessException_invalidEmailDomain_returns400() throws Exception {
        mockMvc.perform(get("/test-handler/invalid-domain"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].detail", containsString("biblione.com")));
    }

    @Test
    @DisplayName("ErrorResponse contém campo 'meta.requestDateTime'")
    void handleBusinessException_responseContainsMetaTimestamp() throws Exception {
        mockMvc.perform(get("/test-handler/invalid-credentials"))
                .andExpect(jsonPath("$.meta.requestDateTime").isNotEmpty());
    }

    // ─── MethodArgumentNotValidException ─────────────────────────────────────

    @Test
    @DisplayName("MethodArgumentNotValidException → 400 com lista de erros de validação")
    void handleValidationException_invalidBody_returns400WithDetails() throws Exception {
        RegisterRequest invalidBody = new RegisterRequest();
        invalidBody.setName("");          // @NotBlank
        invalidBody.setEmail("invalido"); // @Email
        invalidBody.setPassword("abc");   // @Size(min=8)

        mockMvc.perform(post("/test-handler/validation")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidBody)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$.errors[0].code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.errors[0].title").isNotEmpty())
                .andExpect(jsonPath("$.errors[0].detail").isNotEmpty());
    }

    @Test
    @DisplayName("MethodArgumentNotValidException → response inclui o nome do campo com erro")
    void handleValidationException_includesFieldName() throws Exception {
        RegisterRequest invalidBody = new RegisterRequest();
        invalidBody.setName("Jo"); // válido
        invalidBody.setEmail("invalido"); // inválido
        invalidBody.setPassword("senha@1234"); // válido

        mockMvc.perform(post("/test-handler/validation")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidBody)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[*].title", hasItem("email")));
    }

    // ─── Exception genérica ───────────────────────────────────────────────────

    @Test
    @DisplayName("Exception não mapeada → 500 Internal Server Error")
    void handleGenericException_unexpectedError_returns500() throws Exception {
        mockMvc.perform(get("/test-handler/generic-error"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errors[0].code").value("INTERNAL_SERVER_ERROR"));
    }
}
