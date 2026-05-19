package com.sincronia.idp_server.oauth;

import com.sincronia.idp_server.exception.ApiException;
import com.sincronia.idp_server.oauth.dto.IntrospectionResponse;
import com.sincronia.idp_server.oauth.dto.OAuthPasswordStepResult;
import com.sincronia.idp_server.oauth.dto.RevokeResponse;
import com.sincronia.idp_server.oauth.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;
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
            @RequestParam Map<String, String> params,
            HttpServletRequest httpServletRequest
    ) {
        return oauthAuthorizationService.token(
                params.get("grant_type"),
                params.get("client_id"),
                params.get("client_secret"),
                params.get("code"),
                params.get("redirect_uri"),
                params.get("refresh_token"),
                httpServletRequest
        );
    }

    @ResponseBody
    @PostMapping(
            value = "/oauth/revoke",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    public RevokeResponse revoke(
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            HttpServletRequest httpServletRequest
    ) {
        return oauthAuthorizationService.revoke(
                clientId,
                clientSecret,
                token,
                tokenTypeHint,
                httpServletRequest
        );
    }

    @ResponseBody
    @PostMapping(
            value = "/oauth/introspect",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    public IntrospectionResponse introspect(
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam("token") String token
    ) {
        return oauthAuthorizationService.introspect(
                clientId,
                clientSecret,
                token
        );
    }
}