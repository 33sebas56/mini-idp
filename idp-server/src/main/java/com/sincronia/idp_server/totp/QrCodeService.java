package com.sincronia.idp_server.totp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Service
public class QrCodeService {

    public String toDataUri(String text) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();

            var bitMatrix = qrCodeWriter.encode(
                    text,
                    BarcodeFormat.QR_CODE,
                    240,
                    240
            );

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

            return "data:image/png;base64,"
                    + Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (Exception exception) {
            throw new IllegalStateException("Could not create QR code", exception);
        }
    }
}