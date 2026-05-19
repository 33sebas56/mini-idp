package com.sincronia.idp_server.oauth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RevokedAccessTokenRepository extends JpaRepository<RevokedAccessToken, UUID> {

    boolean existsByJti(String jti);
}