package com.sincronia.idp_server.totp;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;

@Service
public class TotpCodeValidator {

    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    private static final int ALLOWED_WINDOW = 1;

    public boolean isValid(String base32Secret, String code) {
        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }

        long currentStep = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;

        for (int offset = -ALLOWED_WINDOW; offset <= ALLOWED_WINDOW; offset++) {
            String candidate = generateCode(base32Secret, currentStep + offset);

            if (constantTimeEquals(candidate, code)) {
                return true;
            }
        }

        return false;
    }

    private String generateCode(String base32Secret, long counter) {
        try {
            byte[] key = Base32.decode(base32Secret);
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));

            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0f;

            int binary =
                    ((hash[offset] & 0x7f) << 24)
                            | ((hash[offset + 1] & 0xff) << 16)
                            | ((hash[offset + 2] & 0xff) << 8)
                            | (hash[offset + 3] & 0xff);

            int otp = binary % (int) Math.pow(10, CODE_DIGITS);

            return String.format("%06d", otp);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not generate TOTP code", exception);
        }
    }

    private boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8)
        );
    }
}