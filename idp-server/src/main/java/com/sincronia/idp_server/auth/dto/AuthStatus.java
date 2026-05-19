package com.sincronia.idp_server.auth.dto;

public enum AuthStatus {
    TOTP_SETUP_REQUIRED,
    TOTP_REQUIRED,
    AUTHENTICATED
}