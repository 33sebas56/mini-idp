package com.sincronia.idp_server.oauth;

import com.sincronia.idp_server.audit.AuditService;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.jwt.IssuedAccessToken;
import com.sincronia.idp_server.jwt.JwtService;
import com.sincronia.idp_server.oauth.dto.OAuthPasswordStepResult;
import com.sincronia.idp_server.oauth.dto.TokenResponse;
import com.sincronia.idp_server.token.TokenService;
import com.sincronia.idp_server.totp.LoginChallenge;
import com.sincronia.idp_server.totp.LoginChallengePurpose;
import com.sincronia.idp_server.totp.LoginChallengeRepository;
import com.sincronia.idp_server.totp.TotpService;
import com.sincronia.idp_server.user.AppUser;
import com.sincronia.idp_server.user.AppUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class OAuthAuthorizationService {

    private static final String AUTHORIZATION_CODE_GRANT = "authorization_code";

    private final OAuthClientRepository oauthClientRepository;
    private final OAuthAuthorizationRequestRepository authorizationRequestRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AppUserRepository appUserRepository;
    private final LoginChallengeRepository loginChallengeRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final TotpService totpService;
    private final JwtService jwtService;
    private final AuditService auditService;

    public OAuthAuthorizationService(
            OAuthClientRepository oauthClientRepository,
            OAuthAuthorizationRequestRepository authorizationRequestRepository,
            AuthorizationCodeRepository authorizationCodeRepository,
            AppUserRepository appUserRepository,
            LoginChallengeRepository loginChallengeRepository,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            TotpService totpService,
            JwtService jwtService,
            AuditService auditService
    ) {
        this.oauthClientRepository = oauthClientRepository;
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.appUserRepository = appUserRepository;
        this.loginChallengeRepository = loginChallengeRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.totpService = totpService;
        this.jwtService = jwtService;
        this.auditService = auditService;
    }

    @Transactional
    public OAuthAuthorizationRequest createAuthorizationRequest(
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state
    ) {
        if (!"code".equals(responseType)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "response_type no soportado");
        }

        OAuthClient client = getEnabledClient(clientId);

        if (!client.getRedirectUri().equals(redirectUri)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "redirect_uri inválida");
        }

        String normalizedScope = normalizeScope(scope, client.getAllowedScopes());

        OAuthAuthorizationRequest authorizationRequest = new OAuthAuthorizationRequest(
                clientId,
                redirectUri,
                state,
                normalizedScope,
                Instant.now().plus(10, ChronoUnit.MINUTES)
        );

        return authorizationRequestRepository.save(authorizationRequest);
    }

    @Transactional
    public OAuthPasswordStepResult completePasswordStep(
            UUID authorizationRequestId,
            String email,
            String password,
            HttpServletRequest httpServletRequest
    ) {
        OAuthAuthorizationRequest authorizationRequest = getValidAuthorizationRequest(authorizationRequestId);

        String normalizedEmail = normalizeEmail(email);

        AppUser user = appUserRepository
                .findByEmail(normalizedEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            auditService.record(user, "OAUTH_PASSWORD_LOGIN_FAILED", httpServletRequest, "Invalid password");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        if (!user.isEnabled()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "La cuenta está deshabilitada");
        }

        if (!user.isEmailVerified()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Debe verificar el correo antes de iniciar sesión");
        }

        if (!totpService.hasEnabledTotp(user)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Debe configurar TOTP antes de usar OAuth");
        }

        String challengeToken = createChallenge(user, LoginChallengePurpose.TOTP_REQUIRED);

        auditService.record(
                user,
                "OAUTH_PASSWORD_ACCEPTED_TOTP_REQUIRED",
                httpServletRequest,
                "OAuth password accepted, TOTP required"
        );

        return new OAuthPasswordStepResult(
                challengeToken,
                "Contraseña válida. Ingrese el código TOTP."
        );
    }

    @Transactional
    public String completeTotpAndCreateRedirect(
            UUID authorizationRequestId,
            String rawChallenge,
            String code,
            HttpServletRequest httpServletRequest
    ) {
        OAuthAuthorizationRequest authorizationRequest = getValidAuthorizationRequest(authorizationRequestId);

        LoginChallenge challenge = getValidChallenge(rawChallenge, LoginChallengePurpose.TOTP_REQUIRED);

        boolean valid = totpService.isValidEnabledCode(challenge.getUser(), code);

        if (!valid) {
            auditService.record(challenge.getUser(), "OAUTH_TOTP_FAILED", httpServletRequest, "Invalid OAuth TOTP code");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Código TOTP inválido");
        }

        String rawCode = tokenService.generateUrlSafeToken();
        String codeHash = tokenService.sha256(rawCode);

        AuthorizationCode authorizationCode = new AuthorizationCode(
                codeHash,
                challenge.getUser(),
                authorizationRequest.getClientId(),
                authorizationRequest.getRedirectUri(),
                authorizationRequest.getScope(),
                Instant.now().plus(5, ChronoUnit.MINUTES)
        );

        authorizationCodeRepository.save(authorizationCode);

        challenge.markConsumed();
        authorizationRequest.markConsumed();

        auditService.record(
                challenge.getUser(),
                "OAUTH_AUTHORIZATION_CODE_ISSUED",
                httpServletRequest,
                "Authorization code issued"
        );

        UriComponentsBuilder redirectBuilder = UriComponentsBuilder
                .fromUriString(authorizationRequest.getRedirectUri())
                .queryParam("code", rawCode);

        if (authorizationRequest.getState() != null && !authorizationRequest.getState().isBlank()) {
            redirectBuilder.queryParam("state", authorizationRequest.getState());
        }

        return redirectBuilder.toUriString();
    }

    @Transactional
    public TokenResponse exchangeAuthorizationCode(
            String grantType,
            String clientId,
            String clientSecret,
            String code,
            String redirectUri,
            HttpServletRequest httpServletRequest
    ) {
        if (!AUTHORIZATION_CODE_GRANT.equals(grantType)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "grant_type no soportado");
        }

        OAuthClient client = getEnabledClient(clientId);

        if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales de cliente inválidas");
        }

        String codeHash = tokenService.sha256(code);

        AuthorizationCode authorizationCode = authorizationCodeRepository
                .findByCodeHash(codeHash)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Código de autorización inválido"));

        if (authorizationCode.isUsed()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El código de autorización ya fue usado");
        }

        if (authorizationCode.isExpired()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El código de autorización expiró");
        }

        if (!authorizationCode.getClientId().equals(clientId)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El código no pertenece a este cliente");
        }

        if (!authorizationCode.getRedirectUri().equals(redirectUri)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "redirect_uri no coincide");
        }

        authorizationCode.markUsed();

        IssuedAccessToken accessToken = jwtService.issueAccessToken(
                authorizationCode.getUser(),
                authorizationCode.getScope()
        );

        auditService.record(
                authorizationCode.getUser(),
                "OAUTH_TOKEN_ISSUED",
                httpServletRequest,
                "Access token issued from authorization code"
        );

        return new TokenResponse(
                accessToken.value(),
                accessToken.tokenType(),
                accessToken.expiresIn(),
                authorizationCode.getScope()
        );
    }

    private OAuthClient getEnabledClient(String clientId) {
        OAuthClient client = oauthClientRepository
                .findByClientId(clientId)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Cliente OAuth inválido"));

        if (!client.isEnabled()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Cliente OAuth deshabilitado");
        }

        return client;
    }

    private OAuthAuthorizationRequest getValidAuthorizationRequest(UUID authorizationRequestId) {
        OAuthAuthorizationRequest authorizationRequest = authorizationRequestRepository
                .findById(authorizationRequestId)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Solicitud de autorización inválida"));

        if (authorizationRequest.isConsumed()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Solicitud de autorización ya fue usada");
        }

        if (authorizationRequest.isExpired()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Solicitud de autorización expirada");
        }

        return authorizationRequest;
    }

    private String createChallenge(AppUser user, LoginChallengePurpose purpose) {
        String rawChallenge = tokenService.generateUrlSafeToken();
        String challengeHash = tokenService.sha256(rawChallenge);

        LoginChallenge challenge = new LoginChallenge(
                user,
                challengeHash,
                purpose,
                Instant.now().plus(10, ChronoUnit.MINUTES)
        );

        loginChallengeRepository.save(challenge);

        return rawChallenge;
    }

    private LoginChallenge getValidChallenge(String rawChallenge, LoginChallengePurpose expectedPurpose) {
        String challengeHash = tokenService.sha256(rawChallenge);

        LoginChallenge challenge = loginChallengeRepository
                .findByChallengeHash(challengeHash)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Challenge inválido"));

        if (challenge.getPurpose() != expectedPurpose) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Challenge inválido para esta operación");
        }

        if (challenge.isConsumed()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Challenge ya fue usado");
        }

        if (challenge.isExpired()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Challenge expirado");
        }

        return challenge;
    }

    private String normalizeScope(String requestedScope, String allowedScopes) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return allowedScopes;
        }

        for (String scope : requestedScope.split(" ")) {
            if (!allowedScopes.contains(scope)) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "Scope no permitido: " + scope);
            }
        }

        return requestedScope.trim();
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}