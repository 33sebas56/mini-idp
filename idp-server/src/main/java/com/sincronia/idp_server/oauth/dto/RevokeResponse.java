package com.sincronia.idp_server.oauth.dto;

public record RevokeResponse(
        boolean revoked,
        String message
) {
}