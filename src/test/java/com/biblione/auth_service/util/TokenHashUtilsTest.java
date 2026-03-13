package com.biblione.auth_service.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class TokenHashUtilsTest {

    // ─── determinismo ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("hash: mesma entrada sempre produz o mesmo resultado")
    void hash_sameInput_returnsSameHash() {
        String token = "meu-refresh-token-secreto";

        String hash1 = TokenHashUtils.hash(token);
        String hash2 = TokenHashUtils.hash(token);

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    @DisplayName("hash: entradas diferentes produzem hashes diferentes")
    void hash_differentInputs_returnDifferentHashes() {
        String hash1 = TokenHashUtils.hash("token-a");
        String hash2 = TokenHashUtils.hash("token-b");

        assertThat(hash1).isNotEqualTo(hash2);
    }

    // ─── formato de saída ─────────────────────────────────────────────────────

    @Test
    @DisplayName("hash: retorna string não vazia")
    void hash_anyInput_returnsNonBlankString() {
        String result = TokenHashUtils.hash("qualquer-token");

        assertThat(result).isNotBlank();
    }

    @Test
    @DisplayName("hash: retorna string codificada em Base64")
    void hash_anyInput_returnsBase64EncodedString() {
        String result = TokenHashUtils.hash("token-para-base64");

        // Se não for Base64 válido, esta linha lançará IllegalArgumentException
        byte[] decoded = Base64.getDecoder().decode(result);
        assertThat(decoded).isNotEmpty();
    }

    @Test
    @DisplayName("hash: saída é SHA-256, portanto 32 bytes → 44 chars em Base64 (com padding)")
    void hash_outputLength_is44CharsBase64() {
        // SHA-256 → 256 bits → 32 bytes → ceil(32/3)*4 = 44 caracteres Base64
        String result = TokenHashUtils.hash("tamanho-fixo");

        assertThat(result).hasSize(44);
    }

    // ─── sensibilidade ────────────────────────────────────────────────────────

    @Test
    @DisplayName("hash: case-sensitive — maiúsculas e minúsculas geram hashes distintos")
    void hash_caseSensitive_differentHashesForDifferentCases() {
        String lowerHash = TokenHashUtils.hash("token");
        String upperHash = TokenHashUtils.hash("TOKEN");

        assertThat(lowerHash).isNotEqualTo(upperHash);
    }

    @Test
    @DisplayName("hash: espaço no token altera o hash")
    void hash_whitespaceMatters() {
        String withSpace    = TokenHashUtils.hash("token ");
        String withoutSpace = TokenHashUtils.hash("token");

        assertThat(withSpace).isNotEqualTo(withoutSpace);
    }

    @Test
    @DisplayName("hash: string vazia → retorna hash válido (não lança exceção)")
    void hash_emptyString_doesNotThrow() {
        assertThatCode(() -> TokenHashUtils.hash(""))
                .doesNotThrowAnyException();

        assertThat(TokenHashUtils.hash("")).isNotBlank();
    }
}
