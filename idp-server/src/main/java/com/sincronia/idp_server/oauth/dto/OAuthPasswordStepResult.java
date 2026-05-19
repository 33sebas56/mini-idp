package com.sincronia.idp_server.oauth.dto;

public record OAuthPasswordStepResult(
        String challengeToken,
        String message
) {
}