package com.sincronia.idp_server.auth.dto;

import com.sincronia.idp_server.jwt.IssuedAccessToken;

public class LoginResponse {

    private final AuthStatus status;
    private final String challengeToken;
    private final String message;
    private final String accessToken;
    private final String tokenType;
    private final Long expiresIn;

    public LoginResponse(AuthStatus status, String challengeToken, String message) {
        this.status = status;
        this.challengeToken = challengeToken;
        this.message = message;
        this.accessToken = null;
        this.tokenType = null;
        this.expiresIn = null;
    }

    public LoginResponse(
            AuthStatus status,
            String challengeToken,
            String message,
            String accessToken,
            String tokenType,
            Long expiresIn
    ) {
        this.status = status;
        this.challengeToken = challengeToken;
        this.message = message;
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    public static LoginResponse authenticated(String message, IssuedAccessToken token) {
        return new LoginResponse(
                AuthStatus.AUTHENTICATED,
                null,
                message,
                token.value(),
                token.tokenType(),
                token.expiresIn()
        );
    }

    public AuthStatus getStatus() {
        return status;
    }

    public String getChallengeToken() {
        return challengeToken;
    }

    public String getMessage() {
        return message;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }
}