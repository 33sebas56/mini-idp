package com.sincronia.idp_server.auth;

import com.sincronia.idp_server.auth.dto.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.register(request, httpServletRequest);
    }

    @GetMapping("/verify-email")
    public Map<String, Object> verifyEmail(
            @RequestParam String token,
            HttpServletRequest httpServletRequest
    ) {
        authService.verifyEmail(token, httpServletRequest);

        return Map.of(
                "status", "VERIFIED",
                "message", "Correo verificado correctamente"
        );
    }

    @PostMapping("/login")
    public LoginResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.login(request, httpServletRequest);
    }

    @PostMapping("/totp/setup")
    public TotpSetupResponse setupTotp(
            @Valid @RequestBody TotpSetupRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.setupTotp(request, httpServletRequest);
    }

    @PostMapping("/totp/confirm")
    public LoginResponse confirmTotp(
            @Valid @RequestBody TotpCodeRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.confirmTotp(request, httpServletRequest);
    }

    @PostMapping("/totp/verify-login")
    public LoginResponse verifyTotpLogin(
            @Valid @RequestBody TotpCodeRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.verifyTotpLogin(request, httpServletRequest);
    }
}