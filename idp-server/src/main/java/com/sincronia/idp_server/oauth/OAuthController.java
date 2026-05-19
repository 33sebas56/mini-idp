package com.sincronia.idp_server.oauth;

import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.oauth.dto.OAuthPasswordStepResult;
import com.sincronia.idp_server.oauth.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.UUID;

@Controller
public class OAuthController {

    private final OAuthAuthorizationService oauthAuthorizationService;

    public OAuthController(OAuthAuthorizationService oauthAuthorizationService) {
        this.oauthAuthorizationService = oauthAuthorizationService;
    }

    @GetMapping("/oauth/authorize")
    public String authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            Model model
    ) {
        try {
            OAuthAuthorizationRequest authorizationRequest = oauthAuthorizationService.createAuthorizationRequest(
                    responseType,
                    clientId,
                    redirectUri,
                    scope,
                    state
            );

            model.addAttribute("authorizationRequestId", authorizationRequest.getId());
            model.addAttribute("clientId", clientId);
            model.addAttribute("redirectUri", redirectUri);
            model.addAttribute("scope", authorizationRequest.getScope());

            return "oauth-login";
        } catch (ApiException exception) {
            model.addAttribute("error", exception.getMessage());
            return "oauth-error";
        }
    }

    @PostMapping("/oauth/login")
    public String login(
            @RequestParam UUID authorizationRequestId,
            @RequestParam String email,
            @RequestParam String password,
            HttpServletRequest httpServletRequest,
            Model model
    ) {
        try {
            OAuthPasswordStepResult result = oauthAuthorizationService.completePasswordStep(
                    authorizationRequestId,
                    email,
                    password,
                    httpServletRequest
            );

            model.addAttribute("authorizationRequestId", authorizationRequestId);
            model.addAttribute("challengeToken", result.challengeToken());
            model.addAttribute("message", result.message());

            return "oauth-totp";
        } catch (ApiException exception) {
            model.addAttribute("authorizationRequestId", authorizationRequestId);
            model.addAttribute("error", exception.getMessage());
            model.addAttribute("email", email);
            return "oauth-login";
        }
    }

    @PostMapping("/oauth/totp")
    public Object totp(
            @RequestParam UUID authorizationRequestId,
            @RequestParam String challengeToken,
            @RequestParam String code,
            HttpServletRequest httpServletRequest,
            Model model
    ) {
        try {
            String redirectUrl = oauthAuthorizationService.completeTotpAndCreateRedirect(
                    authorizationRequestId,
                    challengeToken,
                    code,
                    httpServletRequest
            );

            return new RedirectView(redirectUrl);
        } catch (ApiException exception) {
            model.addAttribute("authorizationRequestId", authorizationRequestId);
            model.addAttribute("challengeToken", challengeToken);
            model.addAttribute("error", exception.getMessage());
            return "oauth-totp";
        }
    }

    @ResponseBody
    @PostMapping(
            value = "/oauth/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    public TokenResponse token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            HttpServletRequest httpServletRequest
    ) {
        return oauthAuthorizationService.exchangeAuthorizationCode(
                grantType,
                clientId,
                clientSecret,
                code,
                redirectUri,
                httpServletRequest
        );
    }
}