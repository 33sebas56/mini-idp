package com.sincronia.idp_server.email;

public interface EmailService {

    void sendVerificationEmail(String to, String verificationLink);
}