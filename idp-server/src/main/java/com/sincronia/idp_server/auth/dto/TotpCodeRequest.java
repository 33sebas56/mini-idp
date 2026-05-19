package com.sincronia.idp_server.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TotpCodeRequest(
        @NotBlank
        String challengeToken,

        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "El código TOTP debe tener 6 dígitos")
        String code
) {
}