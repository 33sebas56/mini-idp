package com.sincronia.idp_server.portal;

import com.sincronia.idp_server.auth.AuthService;
import com.sincronia.idp_server.auth.dto.RegisterRequest;
import com.sincronia.idp_server.exception.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class RegistrationPageController {

    private final AuthService authService;

    public RegistrationPageController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String confirmPassword,
            HttpServletRequest httpServletRequest,
            Model model
    ) {
        try {
            RegisterRequest request = new RegisterRequest(
                    email,
                    password,
                    confirmPassword
            );

            authService.register(request, httpServletRequest);

            model.addAttribute("email", email.trim().toLowerCase());
            return "register-success";
        } catch (ApiException exception) {
            model.addAttribute("error", exception.getMessage());
            model.addAttribute("email", email);
            return "register";
        } catch (Exception exception) {
            model.addAttribute("error", "No se pudo completar el registro. Revise los datos e intente nuevamente.");
            model.addAttribute("email", email);
            return "register";
        }
    }
}