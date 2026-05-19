package com.sincronia.idp_server.auth.dto;

public record TotpSetupResponse(
        String secret,
        String otpauthUri,
        String qrCodeDataUri,
        String message
) {
}