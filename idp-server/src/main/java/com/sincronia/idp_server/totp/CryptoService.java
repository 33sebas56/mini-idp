package com.sincronia.idp_server.totp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class CryptoService {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    private final String encryptionSecret;
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptoService(@Value("${app.security.encryption-secret}") String encryptionSecret) {
        this.encryptionSecret = encryptionSecret;
    }

    public String encrypt(String plainText) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            return Base64.getUrlEncoder().withoutPadding().encodeToString(iv)
                    + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(cipherText);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not encrypt value", exception);
        }
    }

    public String decrypt(String encryptedValue) {
        try {
            String[] parts = encryptedValue.split("\\.");

            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid encrypted value format");
            }

            byte[] iv = Base64.getUrlDecoder().decode(parts[0]);
            byte[] cipherText = Base64.getUrlDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not decrypt value", exception);
        }
    }

    private SecretKeySpec key() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] key = digest.digest(encryptionSecret.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(key, "AES");
        } catch (Exception exception) {
            throw new IllegalStateException("Could not create encryption key", exception);
        }
    }
}