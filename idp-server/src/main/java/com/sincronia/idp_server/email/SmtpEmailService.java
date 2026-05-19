package com.sincronia.idp_server.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class SmtpEmailService implements EmailService {

    private final JavaMailSender mailSender;
    private final String from;

    public SmtpEmailService(
            JavaMailSender mailSender,
            @Value("${app.mail.from}") String from
    ) {
        this.mailSender = mailSender;
        this.from = from;
    }

    @Override
    public void sendVerificationEmail(String to, String verificationLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Verificación de cuenta - Mini IdP");
        message.setText("""
                Hola,

                Recibimos una solicitud para crear una cuenta en Mini IdP.

                Para verificar tu correo, abre este enlace:

                %s

                Este enlace expira en 24 horas.

                Si no solicitaste esta cuenta, ignora este mensaje.
                """.formatted(verificationLink));

        mailSender.send(message);
    }
}