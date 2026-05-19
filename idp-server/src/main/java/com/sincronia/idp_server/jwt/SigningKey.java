package com.sincronia.idp_server.jwt;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "signing_keys")
public class SigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 120)
    private String kid;

    @Column(name = "private_jwk_encrypted", nullable = false, columnDefinition = "text")
    private String privateJwkEncrypted;

    @Column(name = "public_jwk", nullable = false, columnDefinition = "text")
    private String publicJwk;

    @Column(nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    protected SigningKey() {
    }

    public SigningKey(String kid, String privateJwkEncrypted, String publicJwk) {
        this.kid = kid;
        this.privateJwkEncrypted = privateJwkEncrypted;
        this.publicJwk = publicJwk;
        this.active = true;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }

    public String getKid() {
        return kid;
    }

    public String getPrivateJwkEncrypted() {
        return privateJwkEncrypted;
    }

    public String getPublicJwk() {
        return publicJwk;
    }

    public boolean isActive() {
        return active;
    }
}