package com.sincronia.idp_server.auth.dto;

public record LoginResponse(
        AuthStatus status,
        String challengeToken,
        String message
) {
}