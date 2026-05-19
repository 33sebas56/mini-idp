package com.sincronia.idp_server.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.totp.CryptoService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class SigningKeyService {

    private final SigningKeyRepository signingKeyRepository;
    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public SigningKeyService(
            SigningKeyRepository signingKeyRepository,
            CryptoService cryptoService,
            ObjectMapper objectMapper
    ) {
        this.signingKeyRepository = signingKeyRepository;
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public RSAKey getActivePrivateKey() {
        SigningKey signingKey = getOrCreateActiveSigningKey();

        try {
            String privateJwk = cryptoService.decrypt(signingKey.getPrivateJwkEncrypted());
            return RSAKey.parse(privateJwk);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not load private signing key", exception);
        }
    }

    @Transactional(readOnly = true)
    public RSAKey getPublicKeyByKid(String kid) {
        SigningKey signingKey = signingKeyRepository.findByKid(kid)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Clave pública no encontrada para kid"));

        try {
            return RSAKey.parse(signingKey.getPublicJwk());
        } catch (Exception exception) {
            throw new IllegalStateException("Could not parse public signing key", exception);
        }
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> getActivePublicJwks() {
        return signingKeyRepository.findByActiveTrueOrderByCreatedAtDesc()
                .stream()
                .map(this::toPublicJwkMap)
                .toList();
    }

    private Map<String, Object> toPublicJwkMap(SigningKey signingKey) {
        try {
            return objectMapper.readValue(signingKey.getPublicJwk(), Map.class);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not parse public JWK", exception);
        }
    }

    private SigningKey getOrCreateActiveSigningKey() {
        return signingKeyRepository.findFirstByActiveTrueOrderByCreatedAtDesc()
                .orElseGet(this::createSigningKey);
    }

    private SigningKey createSigningKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();

            String kid = UUID.randomUUID().toString();

            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();

            String privateJwk = rsaKey.toJSONString();
            String publicJwk = rsaKey.toPublicJWK().toJSONString();

            SigningKey signingKey = new SigningKey(
                    kid,
                    cryptoService.encrypt(privateJwk),
                    publicJwk
            );

            return signingKeyRepository.save(signingKey);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not create RSA signing key", exception);
        }
    }
}