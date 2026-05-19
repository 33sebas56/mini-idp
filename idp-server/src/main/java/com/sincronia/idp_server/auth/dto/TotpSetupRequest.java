package com.sincronia.idp_server.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record TotpSetupRequest(
        @NotBlank
        String challengeToken
) {
}