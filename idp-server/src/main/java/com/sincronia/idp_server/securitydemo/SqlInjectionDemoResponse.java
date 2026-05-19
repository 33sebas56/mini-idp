package com.sincronia.idp_server.securitydemo;

public record SqlInjectionDemoResponse(
        String input,
        boolean found,
        int returnedRows,
        String message
) {
}