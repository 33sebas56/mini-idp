package com.sincronia.idp_server.jwt;

public record IssuedAccessToken(
        String value,
        String tokenType,
        long expiresIn
) {
}