package com.sincronia.idp_server.jwt;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    Optional<SigningKey> findFirstByActiveTrueOrderByCreatedAtDesc();

    List<SigningKey> findByActiveTrueOrderByCreatedAtDesc();

    Optional<SigningKey> findByKid(String kid);
}