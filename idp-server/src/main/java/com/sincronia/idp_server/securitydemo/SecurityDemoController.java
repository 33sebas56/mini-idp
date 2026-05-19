package com.sincronia.idp_server.securitydemo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityDemoController {

    private final SafeUserLookupService safeUserLookupService;

    public SecurityDemoController(SafeUserLookupService safeUserLookupService) {
        this.safeUserLookupService = safeUserLookupService;
    }

    @GetMapping("/security/sql-injection-demo")
    public SqlInjectionDemoResponse sqlInjectionDemo(@RequestParam String email) {
        return safeUserLookupService.safeLookupByEmail(email);
    }
}