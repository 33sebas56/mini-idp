package com.sincronia.idp_server.totp;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface LoginChallengeRepository extends JpaRepository<LoginChallenge, UUID> {

    Optional<LoginChallenge> findByChallengeHash(String challengeHash);
}