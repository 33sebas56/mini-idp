package com.sincronia.idp_server.totp;

import com.sincronia.idp_server.user.AppUser;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "totp_credentials")
public class TotpCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private AppUser user;

    @Column(name = "secret_encrypted", nullable = false, columnDefinition = "text")
    private String secretEncrypted;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected TotpCredential() {
    }

    public TotpCredential(AppUser user, String secretEncrypted) {
        this.user = user;
        this.secretEncrypted = secretEncrypted;
        this.enabled = false;
    }

    @PrePersist
    void prePersist() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = Instant.now();
    }

    public String getSecretEncrypted() {
        return secretEncrypted;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void replaceSecret(String secretEncrypted) {
        this.secretEncrypted = secretEncrypted;
        this.enabled = false;
    }

    public void markEnabled() {
        this.enabled = true;
    }
}