package com.sincronia.idp_server.totp;

import com.sincronia.idp_server.user.AppUser;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "login_challenges")
public class LoginChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(name = "challenge_hash", nullable = false, unique = true, length = 64)
    private String challengeHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private LoginChallengePurpose purpose;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected LoginChallenge() {
    }

    public LoginChallenge(AppUser user, String challengeHash, LoginChallengePurpose purpose, Instant expiresAt) {
        this.user = user;
        this.challengeHash = challengeHash;
        this.purpose = purpose;
        this.expiresAt = expiresAt;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }

    public AppUser getUser() {
        return user;
    }

    public LoginChallengePurpose getPurpose() {
        return purpose;
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