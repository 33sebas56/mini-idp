package com.sincronia.idp_server.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class OAuthClientInitializer implements ApplicationRunner {

    private final OAuthClientRepository oauthClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final String clientId;
    private final String clientSecret;
    private final String name;
    private final String redirectUri;
    private final String allowedScopes;

    public OAuthClientInitializer(
            OAuthClientRepository oauthClientRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.oauth.default-client.client-id}") String clientId,
            @Value("${app.oauth.default-client.client-secret}") String clientSecret,
            @Value("${app.oauth.default-client.name}") String name,
            @Value("${app.oauth.default-client.redirect-uri}") String redirectUri,
            @Value("${app.oauth.default-client.allowed-scopes}") String allowedScopes
    ) {
        this.oauthClientRepository = oauthClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.name = name;
        this.redirectUri = redirectUri;
        this.allowedScopes = allowedScopes;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (oauthClientRepository.existsByClientId(clientId)) {
            return;
        }

        OAuthClient client = new OAuthClient(
                clientId,
                passwordEncoder.encode(clientSecret),
                name,
                redirectUri,
                allowedScopes
        );

        oauthClientRepository.save(client);
    }
}