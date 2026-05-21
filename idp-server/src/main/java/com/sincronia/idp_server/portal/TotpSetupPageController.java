package com.sincronia.idp_server.portal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TotpSetupPageController {

    @GetMapping("/totp-setup")
    public String totpSetup() {
        return "totp-setup";
    }
}