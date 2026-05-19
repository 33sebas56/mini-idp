package com.sincronia.idp_server.oauth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, UUID> {

    Optional<AuthorizationCode> findByCodeHash(String codeHash);
}