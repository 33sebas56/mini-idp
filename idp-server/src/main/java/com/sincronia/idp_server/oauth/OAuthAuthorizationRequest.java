package com.sincronia.idp_server.oauth;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "oauth_authorization_requests")
public class OAuthAuthorizationRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "client_id", nullable = false, length = 120)
    private String clientId;

    @Column(name = "redirect_uri", nullable = false, length = 500)
    private String redirectUri;

    @Column(length = 500)
    private String state;

    @Column(nullable = false, length = 500)
    private String scope;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected OAuthAuthorizationRequest() {
    }

    public OAuthAuthorizationRequest(
            String clientId,
            String redirectUri,
            String state,
            String scope,
            Instant expiresAt
    ) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.scope = scope;
        this.expiresAt = expiresAt;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }

    public String getScope() {
        return scope;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public void markConsumed() {
        this.consumedAt = Instant.now();
    }
}