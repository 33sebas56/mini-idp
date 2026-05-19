package com.sincronia.idp_server.jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private final SigningKeyService signingKeyService;

    public JwksController(SigningKeyService signingKeyService) {
        this.signingKeyService = signingKeyService;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return Map.of(
                "keys", signingKeyService.getActivePublicJwks()
        );
    }
}