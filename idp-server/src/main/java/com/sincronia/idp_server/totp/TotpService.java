package com.sincronia.idp_server.totp;

import com.sincronia.idp_server.auth.dto.TotpSetupResponse;
import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.user.AppUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Service
public class TotpService {

    private final TotpCredentialRepository totpCredentialRepository;
    private final CryptoService cryptoService;
    private final TotpCodeValidator totpCodeValidator;
    private final QrCodeService qrCodeService;
    private final String issuer;
    private final SecureRandom secureRandom = new SecureRandom();

    public TotpService(
            TotpCredentialRepository totpCredentialRepository,
            CryptoService cryptoService,
            TotpCodeValidator totpCodeValidator,
            QrCodeService qrCodeService,
            @Value("${app.totp.issuer}") String issuer
    ) {
        this.totpCredentialRepository = totpCredentialRepository;
        this.cryptoService = cryptoService;
        this.totpCodeValidator = totpCodeValidator;
        this.qrCodeService = qrCodeService;
        this.issuer = issuer;
    }

    public boolean hasEnabledTotp(AppUser user) {
        return totpCredentialRepository.findByUserAndEnabledTrue(user).isPresent();
    }

    public TotpSetupResponse createOrReplacePendingSecret(AppUser user) {
        String secret = generateSecret();

        TotpCredential credential = totpCredentialRepository
                .findByUser(user)
                .orElseGet(() -> new TotpCredential(user, cryptoService.encrypt(secret)));

        credential.replaceSecret(cryptoService.encrypt(secret));
        totpCredentialRepository.save(credential);

        String otpauthUri = buildOtpAuthUri(user.getEmail(), secret);
        String qrCodeDataUri = qrCodeService.toDataUri(otpauthUri);

        return new TotpSetupResponse(
                secret,
                otpauthUri,
                qrCodeDataUri,
                "Escanee el QR o registre manualmente el secreto en su aplicación autenticadora."
        );
    }

    public boolean isValidPendingCode(AppUser user, String code) {
        TotpCredential credential = totpCredentialRepository
                .findByUser(user)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "No existe un secreto TOTP pendiente"));

        String secret = cryptoService.decrypt(credential.getSecretEncrypted());
        return totpCodeValidator.isValid(secret, code);
    }

    public boolean isValidEnabledCode(AppUser user, String code) {
        TotpCredential credential = totpCredentialRepository
                .findByUserAndEnabledTrue(user)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El usuario no tiene TOTP habilitado"));

        String secret = cryptoService.decrypt(credential.getSecretEncrypted());
        return totpCodeValidator.isValid(secret, code);
    }

    public void enableTotp(AppUser user) {
        TotpCredential credential = totpCredentialRepository
                .findByUser(user)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "No existe un secreto TOTP pendiente"));

        credential.markEnabled();
        totpCredentialRepository.save(credential);
    }

    private String generateSecret() {
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return Base32.encode(bytes);
    }

    private String buildOtpAuthUri(String email, String secret) {
        String label = encode(issuer + ":" + email);

        return "otpauth://totp/"
                + label
                + "?secret=" + secret
                + "&issuer=" + encode(issuer)
                + "&algorithm=SHA1"
                + "&digits=6"
                + "&period=30";
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }
}