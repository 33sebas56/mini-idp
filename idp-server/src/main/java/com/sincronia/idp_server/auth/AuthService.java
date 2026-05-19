package com.sincronia.idp_server.auth;

import com.sincronia.idp_server.audit.AuditService;
import com.sincronia.idp_server.auth.dto.*;
import com.sincronia.idp_server.email.EmailService;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.token.TokenService;
import com.sincronia.idp_server.totp.*;
import com.sincronia.idp_server.user.AppUser;
import com.sincronia.idp_server.user.AppUserRepository;
import com.sincronia.idp_server.verification.EmailVerificationToken;
import com.sincronia.idp_server.verification.EmailVerificationTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.sincronia.idp_server.jwt.JwtService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class AuthService {

    private final AppUserRepository appUserRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final LoginChallengeRepository loginChallengeRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final TotpService totpService;
    private final String issuer;
    private final JwtService jwtService;

    public AuthService(
            AppUserRepository appUserRepository,
            EmailVerificationTokenRepository emailVerificationTokenRepository,
            LoginChallengeRepository loginChallengeRepository,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            EmailService emailService,
            AuditService auditService,
            TotpService totpService,
            JwtService jwtService,
            @Value("${app.security.issuer}") String issuer
    ) {
        this.appUserRepository = appUserRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.loginChallengeRepository = loginChallengeRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.emailService = emailService;
        this.auditService = auditService;
        this.totpService = totpService;
        this.issuer = issuer;
        this.jwtService = jwtService;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request, HttpServletRequest httpServletRequest) {
        String email = normalizeEmail(request.email());

        if (!request.password().equals(request.confirmPassword())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "La contraseña y su confirmación no coinciden");
        }

        if (appUserRepository.existsByEmail(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ya existe una cuenta registrada con ese correo");
        }

        String passwordHash = passwordEncoder.encode(request.password());
        AppUser user = appUserRepository.save(new AppUser(email, passwordHash));

        String rawToken = tokenService.generateUrlSafeToken();
        String tokenHash = tokenService.sha256(rawToken);

        EmailVerificationToken verificationToken = new EmailVerificationToken(
                user,
                tokenHash,
                Instant.now().plus(24, ChronoUnit.HOURS)
        );

        emailVerificationTokenRepository.save(verificationToken);

        String verificationLink = issuer
                + "/auth/verify-email?token="
                + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);

        try {
            emailService.sendVerificationEmail(email, verificationLink);
        } catch (RuntimeException exception) {
            throw new ApiException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "No se pudo enviar el correo de verificación. Revise la configuración SMTP."
            );
        }

        auditService.record(user, "USER_REGISTERED", httpServletRequest, "Verification email sent");

        return new RegisterResponse(
                email,
                "Usuario registrado. Revise su correo para verificar la cuenta."
        );
    }

    @Transactional
    public void verifyEmail(String rawToken, HttpServletRequest httpServletRequest) {
        String tokenHash = tokenService.sha256(rawToken);

        EmailVerificationToken verificationToken = emailVerificationTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Token de verificación inválido"));

        if (verificationToken.isUsed()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El token de verificación ya fue usado");
        }

        if (verificationToken.isExpired()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El token de verificación expiró");
        }

        AppUser user = verificationToken.getUser();
        user.markEmailVerified();
        verificationToken.markUsed();

        auditService.record(user, "EMAIL_VERIFIED", httpServletRequest, "Email verified successfully");
    }

    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpServletRequest) {
        String email = normalizeEmail(request.email());

        AppUser user = appUserRepository
                .findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            auditService.record(user, "LOGIN_FAILED", httpServletRequest, "Invalid password");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        if (!user.isEnabled()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "La cuenta está deshabilitada");
        }

        if (!user.isEmailVerified()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Debe verificar el correo antes de iniciar sesión");
        }

        if (totpService.hasEnabledTotp(user)) {
            String challengeToken = createChallenge(user, LoginChallengePurpose.TOTP_REQUIRED);
            auditService.record(user, "PASSWORD_LOGIN_OK_TOTP_REQUIRED", httpServletRequest, "Password accepted, TOTP required");

            return new LoginResponse(
                    AuthStatus.TOTP_REQUIRED,
                    challengeToken,
                    "Contraseña válida. Ingrese el código TOTP."
            );
        }

        String challengeToken = createChallenge(user, LoginChallengePurpose.TOTP_SETUP);
        auditService.record(user, "PASSWORD_LOGIN_OK_TOTP_SETUP_REQUIRED", httpServletRequest, "Password accepted, TOTP setup required");

        return new LoginResponse(
                AuthStatus.TOTP_SETUP_REQUIRED,
                challengeToken,
                "Contraseña válida. Debe configurar TOTP."
        );
    }

    @Transactional
    public TotpSetupResponse setupTotp(TotpSetupRequest request, HttpServletRequest httpServletRequest) {
        LoginChallenge challenge = getValidChallenge(
                request.challengeToken(),
                LoginChallengePurpose.TOTP_SETUP
        );

        TotpSetupResponse response = totpService.createOrReplacePendingSecret(challenge.getUser());

        auditService.record(
                challenge.getUser(),
                "TOTP_SETUP_STARTED",
                httpServletRequest,
                "TOTP secret generated"
        );

        return response;
    }

    @Transactional
    public LoginResponse confirmTotp(TotpCodeRequest request, HttpServletRequest httpServletRequest) {
        LoginChallenge challenge = getValidChallenge(
                request.challengeToken(),
                LoginChallengePurpose.TOTP_SETUP
        );

        boolean valid = totpService.isValidPendingCode(challenge.getUser(), request.code());

        if (!valid) {
            auditService.record(challenge.getUser(), "TOTP_SETUP_FAILED", httpServletRequest, "Invalid TOTP setup code");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Código TOTP inválido");
        }

        totpService.enableTotp(challenge.getUser());
        challenge.markConsumed();

        auditService.record(challenge.getUser(), "TOTP_ENABLED", httpServletRequest, "TOTP enabled successfully");

        return LoginResponse.authenticated(
                "TOTP configurado correctamente. Autenticación completada.",
                jwtService.issueAccessToken(challenge.getUser())
        );
    }

    @Transactional
    public LoginResponse verifyTotpLogin(TotpCodeRequest request, HttpServletRequest httpServletRequest) {
        LoginChallenge challenge = getValidChallenge(
                request.challengeToken(),
                LoginChallengePurpose.TOTP_REQUIRED
        );

        boolean valid = totpService.isValidEnabledCode(challenge.getUser(), request.code());

        if (!valid) {
            auditService.record(challenge.getUser(), "TOTP_LOGIN_FAILED", httpServletRequest, "Invalid TOTP login code");
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Código TOTP inválido");
        }

        challenge.markConsumed();

        auditService.record(challenge.getUser(), "LOGIN_COMPLETED", httpServletRequest, "Password and TOTP accepted");

        return LoginResponse.authenticated(
                "Autenticación completada.",
                jwtService.issueAccessToken(challenge.getUser())
        );
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

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}