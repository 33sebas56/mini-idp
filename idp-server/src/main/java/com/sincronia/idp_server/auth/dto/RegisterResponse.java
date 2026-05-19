package com.sincronia.idp_server.auth.dto;

public record RegisterResponse(
        String email,
        String message
) {
}