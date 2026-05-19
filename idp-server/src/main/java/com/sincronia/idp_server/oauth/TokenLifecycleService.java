package com.sincronia.idp_server.oauth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sincronia.idp_server.audit.AuditService;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.jwt.IssuedAccessToken;
import com.sincronia.idp_server.jwt.JwtService;
import com.sincronia.idp_server.oauth.dto.IntrospectionResponse;
import com.sincronia.idp_server.oauth.dto.RevokeResponse;
import com.sincronia.idp_server.oauth.dto.TokenResponse;
import com.sincronia.idp_server.token.TokenService;
import com.sincronia.idp_server.user.AppUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class TokenLifecycleService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RevokedAccessTokenRepository revokedAccessTokenRepository;
    private final OAuthClientRepository oauthClientRepository;
    private final TokenService tokenService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public TokenLifecycleService(
            RefreshTokenRepository refreshTokenRepository,
            RevokedAccessTokenRepository revokedAccessTokenRepository,
            OAuthClientRepository oauthClientRepository,
            TokenService tokenService,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            AuditService auditService
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.revokedAccessTokenRepository = revokedAccessTokenRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.tokenService = tokenService;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional
    public String issueRefreshToken(AppUser user, String clientId, String scope) {
        String rawRefreshToken = tokenService.generateUrlSafeToken();
        String refreshTokenHash = tokenService.sha256(rawRefreshToken);

        RefreshToken refreshToken = new RefreshToken(
                refreshTokenHash,
                user,
                clientId,
                scope,
                Instant.now().plus(7, ChronoUnit.DAYS)
        );

        refreshTokenRepository.save(refreshToken);

        return rawRefreshToken;
    }

    @Transactional
    public TokenResponse exchangeRefreshToken(
            String clientId,
            String clientSecret,
            String rawRefreshToken,
            HttpServletRequest request
    ) {
        validateClient(clientId, clientSecret);

        String refreshTokenHash = tokenService.sha256(rawRefreshToken);

        RefreshToken oldRefreshToken = refreshTokenRepository
                .findByTokenHash(refreshTokenHash)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token inválido"));

        if (!oldRefreshToken.getClientId().equals(clientId)) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token no pertenece al cliente");
        }

        if (!oldRefreshToken.isActive()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token expirado o revocado");
        }

        IssuedAccessToken newAccessToken = jwtService.issueAccessToken(
                oldRefreshToken.getUser(),
                oldRefreshToken.getScope()
        );

        String newRawRefreshToken = tokenService.generateUrlSafeToken();
        String newRefreshTokenHash = tokenService.sha256(newRawRefreshToken);

        RefreshToken newRefreshToken = new RefreshToken(
                newRefreshTokenHash,
                oldRefreshToken.getUser(),
                clientId,
                oldRefreshToken.getScope(),
                Instant.now().plus(7, ChronoUnit.DAYS)
        );

        refreshTokenRepository.save(newRefreshToken);
        oldRefreshToken.replaceWith(newRefreshTokenHash);

        auditService.record(
                oldRefreshToken.getUser(),
                "OAUTH_REFRESH_TOKEN_ROTATED",
                request,
                "Refresh token rotated and new access token issued"
        );

        return new TokenResponse(
                newAccessToken.value(),
                newAccessToken.tokenType(),
                newAccessToken.expiresIn(),
                newRawRefreshToken,
                oldRefreshToken.getScope()
        );
    }

    @Transactional
    public RevokeResponse revoke(
            String clientId,
            String clientSecret,
            String token,
            String tokenTypeHint,
            HttpServletRequest request
    ) {
        validateClient(clientId, clientSecret);

        if ("refresh_token".equals(tokenTypeHint)) {
            return revokeRefreshToken(token, request);
        }

        if ("access_token".equals(tokenTypeHint)) {
            return revokeAccessToken(token, request);
        }

        RevokeResponse refreshResult = revokeRefreshToken(token, request);

        if (refreshResult.revoked()) {
            return refreshResult;
        }

        return revokeAccessToken(token, request);
    }

    @Transactional(readOnly = true)
    public IntrospectionResponse introspect(
            String clientId,
            String clientSecret,
            String token
    ) {
        validateClient(clientId, clientSecret);

        if (token == null || token.isBlank()) {
            return IntrospectionResponse.inactive();
        }

        if (token.contains(".")) {
            return introspectAccessToken(token);
        }

        return introspectRefreshToken(token);
    }

    private RevokeResponse revokeRefreshToken(String rawRefreshToken, HttpServletRequest request) {
        String tokenHash = tokenService.sha256(rawRefreshToken);

        return refreshTokenRepository.findByTokenHash(tokenHash)
                .map(refreshToken -> {
                    if (!refreshToken.isRevoked()) {
                        refreshToken.revoke();

                        auditService.record(
                                refreshToken.getUser(),
                                "OAUTH_REFRESH_TOKEN_REVOKED",
                                request,
                                "Refresh token revoked"
                        );
                    }

                    return new RevokeResponse(true, "Refresh token revocado");
                })
                .orElseGet(() -> new RevokeResponse(false, "Refresh token no encontrado"));
    }

    private RevokeResponse revokeAccessToken(String accessToken, HttpServletRequest request) {
        try {
            SignedJWT signedJWT = jwtService.parseAndVerify(accessToken);

            if (jwtService.isExpired(signedJWT)) {
                return new RevokeResponse(false, "Access token expirado");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String jti = claims.getJWTID();

            if (jti == null || jti.isBlank()) {
                return new RevokeResponse(false, "Access token sin jti");
            }

            if (!revokedAccessTokenRepository.existsByJti(jti)) {
                Date expiration = claims.getExpirationTime();

                revokedAccessTokenRepository.save(
                        new RevokedAccessToken(jti, expiration.toInstant())
                );
            }

            auditService.record(
                    null,
                    "OAUTH_ACCESS_TOKEN_REVOKED",
                    request,
                    "Access token jti revoked: " + jti
            );

            return new RevokeResponse(true, "Access token revocado");
        } catch (Exception exception) {
            return new RevokeResponse(false, "Access token inválido");
        }
    }

    private IntrospectionResponse introspectAccessToken(String token) {
        try {
            SignedJWT signedJWT = jwtService.parseAndVerify(token);

            if (jwtService.isExpired(signedJWT)) {
                return IntrospectionResponse.inactive();
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            if (claims.getJWTID() == null || revokedAccessTokenRepository.existsByJti(claims.getJWTID())) {
                return IntrospectionResponse.inactive();
            }

            return new IntrospectionResponse(
                    true,
                    "access_token",
                    null,
                    claims.getSubject(),
                    claims.getIssuer(),
                    claims.getAudience(),
                    claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant().getEpochSecond() : null,
                    claims.getIssueTime() != null ? claims.getIssueTime().toInstant().getEpochSecond() : null,
                    claims.getJWTID(),
                    claims.getStringClaim("scope"),
                    claims.getStringClaim("email")
            );
        } catch (Exception exception) {
            return IntrospectionResponse.inactive();
        }
    }

    private IntrospectionResponse introspectRefreshToken(String rawRefreshToken) {
        String tokenHash = tokenService.sha256(rawRefreshToken);

        return refreshTokenRepository.findByTokenHash(tokenHash)
                .filter(RefreshToken::isActive)
                .map(refreshToken -> new IntrospectionResponse(
                        true,
                        "refresh_token",
                        refreshToken.getClientId(),
                        refreshToken.getUser().getId().toString(),
                        null,
                        null,
                        refreshToken.getExpiresAt().getEpochSecond(),
                        null,
                        null,
                        refreshToken.getScope(),
                        refreshToken.getUser().getEmail()
                ))
                .orElseGet(IntrospectionResponse::inactive);
    }

    private OAuthClient validateClient(String clientId, String clientSecret) {
        OAuthClient client = oauthClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Cliente OAuth inválido"));

        if (!client.isEnabled()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Cliente OAuth deshabilitado");
        }

        if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales de cliente inválidas");
        }

        return client;
    }
}