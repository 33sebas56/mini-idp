package com.sincronia.client_app.resource;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ProtectedResourceController {

    @GetMapping("/api/profile")
    public Map<String, Object> profile(JwtAuthenticationToken authentication) {
        return Map.of(
                "message", "Token validado correctamente por client-app",
                "subject", authentication.getToken().getSubject(),
                "issuer", authentication.getToken().getIssuer().toString(),
                "audience", authentication.getToken().getAudience(),
                "email", authentication.getToken().getClaimAsString("email"),
                "scope", authentication.getToken().getClaimAsString("scope"),
                "jti", authentication.getToken().getId()
        );
    }
}