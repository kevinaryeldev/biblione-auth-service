package com.biblione.auth_service.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.OffsetDateTime;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        List<ErrorDetail> errors,
        Meta meta
) {
    public record ErrorDetail(
            String code,
            String title,
            String detail
    ) {}

    public record Meta(
            OffsetDateTime requestDateTime
    ) {}

    public static ErrorResponse of(String code, String title, String detail) {
        return new ErrorResponse(
                List.of(new ErrorDetail(code, title, detail)),
                new Meta(OffsetDateTime.now())
        );
    }

    public static ErrorResponse ofValidation(List<ErrorDetail> details) {
        return new ErrorResponse(
                details,
                new Meta(OffsetDateTime.now())
        );
    }
}