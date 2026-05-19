package com.sincronia.idp_server.jwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.user.AppUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private static final String DEFAULT_SCOPE = "openid profile email";

    private final SigningKeyService signingKeyService;
    private final String issuer;
    private final String audience;
    private final long accessTokenMinutes;

    public JwtService(
            SigningKeyService signingKeyService,
            @Value("${app.security.issuer}") String issuer,
            @Value("${app.jwt.audience}") String audience,
            @Value("${app.jwt.access-token-minutes}") long accessTokenMinutes
    ) {
        this.signingKeyService = signingKeyService;
        this.issuer = issuer;
        this.audience = audience;
        this.accessTokenMinutes = accessTokenMinutes;
    }

    public IssuedAccessToken issueAccessToken(AppUser user) {
        return issueAccessToken(user, DEFAULT_SCOPE);
    }

    public IssuedAccessToken issueAccessToken(AppUser user, String scope) {
        try {
            Instant now = Instant.now();
            Instant expiresAt = now.plus(accessTokenMinutes, ChronoUnit.MINUTES);

            var activeKey = signingKeyService.getActivePrivateKey();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(user.getId().toString())
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiresAt))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("email", user.getEmail())
                    .claim("email_verified", user.isEmailVerified())
                    .claim("scope", normalizeScope(scope))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(JOSEObjectType.JWT)
                            .keyID(activeKey.getKeyID())
                            .build(),
                    claims
            );

            signedJWT.sign(new RSASSASigner(activeKey.toRSAPrivateKey()));

            return new IssuedAccessToken(
                    signedJWT.serialize(),
                    "Bearer",
                    accessTokenMinutes * 60
            );
        } catch (Exception exception) {
            throw new IllegalStateException("Could not issue access token", exception);
        }
    }

    public SignedJWT parseAndVerify(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            String kid = signedJWT.getHeader().getKeyID();

            if (kid == null || kid.isBlank()) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Token sin kid");
            }

            var publicKey = signingKeyService.getPublicKeyByKid(kid);

            boolean validSignature = signedJWT.verify(
                    new RSASSAVerifier(publicKey.toRSAPublicKey())
            );

            if (!validSignature) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Firma JWT inválida");
            }

            return signedJWT;
        } catch (ApiException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Token JWT inválido");
        }
    }

    public boolean isExpired(SignedJWT signedJWT) {
        try {
            Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();

            if (expiration == null) {
                return true;
            }

            return Instant.now().isAfter(expiration.toInstant());
        } catch (Exception exception) {
            return true;
        }
    }

    public long expirationEpochSeconds(SignedJWT signedJWT) {
        try {
            Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();

            if (expiration == null) {
                return Instant.now().getEpochSecond();
            }

            return expiration.toInstant().getEpochSecond();
        } catch (Exception exception) {
            return Instant.now().getEpochSecond();
        }
    }

    private String normalizeScope(String scope) {
        if (scope == null || scope.isBlank()) {
            return DEFAULT_SCOPE;
        }

        return scope.trim();
    }
}