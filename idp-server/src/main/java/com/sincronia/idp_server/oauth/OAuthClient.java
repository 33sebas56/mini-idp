package com.sincronia.idp_server.oauth;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "oauth_clients")
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "client_id", nullable = false, unique = true, length = 120)
    private String clientId;

    @Column(name = "client_secret_hash", nullable = false)
    private String clientSecretHash;

    @Column(nullable = false, length = 160)
    private String name;

    @Column(name = "redirect_uri", nullable = false, length = 500)
    private String redirectUri;

    @Column(name = "allowed_scopes", nullable = false, length = 500)
    private String allowedScopes;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected OAuthClient() {
    }

    public OAuthClient(
            String clientId,
            String clientSecretHash,
            String name,
            String redirectUri,
            String allowedScopes
    ) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.name = name;
        this.redirectUri = redirectUri;
        this.allowedScopes = allowedScopes;
        this.enabled = true;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public String getName() {
        return name;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getAllowedScopes() {
        return allowedScopes;
    }

    public boolean isEnabled() {
        return enabled;
    }
}