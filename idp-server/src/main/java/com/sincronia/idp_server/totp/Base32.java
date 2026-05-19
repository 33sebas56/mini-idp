package com.sincronia.idp_server.totp;

import java.io.ByteArrayOutputStream;

public final class Base32 {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32() {
    }

    public static String encode(byte[] data) {
        StringBuilder result = new StringBuilder();

        int buffer = 0;
        int bitsLeft = 0;

        for (byte value : data) {
            buffer = (buffer << 8) | (value & 0xff);
            bitsLeft += 8;

            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 31;
                bitsLeft -= 5;
                result.append(ALPHABET.charAt(index));
            }
        }

        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 31;
            result.append(ALPHABET.charAt(index));
        }

        return result.toString();
    }

    public static byte[] decode(String value) {
        String normalized = value
                .replace("=", "")
                .replace(" ", "")
                .trim()
                .toUpperCase();

        int buffer = 0;
        int bitsLeft = 0;

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (char character : normalized.toCharArray()) {
            int index = ALPHABET.indexOf(character);

            if (index < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: " + character);
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }

        return output.toByteArray();
    }
}