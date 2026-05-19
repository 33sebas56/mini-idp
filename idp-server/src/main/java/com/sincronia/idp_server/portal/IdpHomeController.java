package com.sincronia.idp_server.portal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IdpHomeController {

    @GetMapping("/")
    public String home() {
        return "idp-home";
    }
}