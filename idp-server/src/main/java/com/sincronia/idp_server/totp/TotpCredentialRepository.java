package com.sincronia.idp_server.totp;

import com.sincronia.idp_server.user.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface TotpCredentialRepository extends JpaRepository<TotpCredential, UUID> {

    Optional<TotpCredential> findByUser(AppUser user);

    Optional<TotpCredential> findByUserAndEnabledTrue(AppUser user);
}