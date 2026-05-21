package com.sincronia.client_app.oauth;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

@Controller
public class OAuthClientController {

    private final RestClient restClient;
    private final JwtDecoder jwtDecoder;
    private final String authorizationUri;
    private final String tokenUri;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String scope;

    public OAuthClientController(
            RestClient restClient,
            JwtDecoder jwtDecoder,
            @Value("${app.idp.authorization-uri}") String authorizationUri,
            @Value("${app.idp.token-uri}") String tokenUri,
            @Value("${app.oauth.client-id}") String clientId,
            @Value("${app.oauth.client-secret}") String clientSecret,
            @Value("${app.oauth.redirect-uri}") String redirectUri,
            @Value("${app.oauth.scope}") String scope
    ) {
        this.restClient = restClient;
        this.jwtDecoder = jwtDecoder;
        this.authorizationUri = authorizationUri;
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scope = scope;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login(HttpSession session) {
        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth_state", state);

        String redirect = UriComponentsBuilder
                .fromUriString(authorizationUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scope)
                .queryParam("state", state)
                .toUriString();

        return "redirect:" + redirect;
    }

    @GetMapping("/callback")
    public String callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            HttpSession session,
            Model model
    ) {
        if (error != null) {
            model.addAttribute("error", error);
            return "error";
        }

        String expectedState = (String) session.getAttribute("oauth_state");

        if (expectedState == null || !expectedState.equals(state)) {
            model.addAttribute("error", "Estado OAuth inválido");
            return "error";
        }

        if (code == null || code.isBlank()) {
            model.addAttribute("error", "No se recibió código de autorización");
            return "error";
        }

        TokenResponse tokenResponse = exchangeCodeForToken(code);

        session.setAttribute("access_token", tokenResponse.accessToken());
        session.setAttribute("refresh_token", tokenResponse.refreshToken());
        session.removeAttribute("oauth_state");

        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        String accessToken = (String) session.getAttribute("access_token");
        String refreshToken = (String) session.getAttribute("refresh_token");

        if (accessToken == null || accessToken.isBlank()) {
            return "redirect:/login";
        }

        Jwt jwt = jwtDecoder.decode(accessToken);

        model.addAttribute("email", jwt.getClaimAsString("email"));
        model.addAttribute("subject", jwt.getSubject());
        model.addAttribute("issuer", jwt.getIssuer().toString());
        model.addAttribute("audience", jwt.getAudience());
        model.addAttribute("scope", jwt.getClaimAsString("scope"));
        model.addAttribute("jti", jwt.getId());
        model.addAttribute("tokenPreview", preview(accessToken));
        model.addAttribute("refreshTokenPreview", preview(refreshToken));

        return "dashboard";
    }

    @GetMapping("/protected-profile")
    public String protectedProfile(HttpSession session, Model model) {
        String accessToken = (String) session.getAttribute("access_token");

        if (accessToken == null || accessToken.isBlank()) {
            return "redirect:/login";
        }

        Jwt jwt = jwtDecoder.decode(accessToken);

        model.addAttribute("message", "Token validado correctamente por client-app usando el JWKS público del IdP.");
        model.addAttribute("email", jwt.getClaimAsString("email"));
        model.addAttribute("subject", jwt.getSubject());
        model.addAttribute("issuer", jwt.getIssuer().toString());
        model.addAttribute("audience", jwt.getAudience());
        model.addAttribute("scope", jwt.getClaimAsString("scope"));
        model.addAttribute("jti", jwt.getId());

        return "protected-profile";
    }

    @GetMapping("/refresh-token")
    public String refreshToken(HttpSession session) {
        String refreshToken = (String) session.getAttribute("refresh_token");

        if (refreshToken == null || refreshToken.isBlank()) {
            return "redirect:/login";
        }

        TokenResponse tokenResponse = exchangeRefreshToken(refreshToken);

        session.setAttribute("access_token", tokenResponse.accessToken());
        session.setAttribute("refresh_token", tokenResponse.refreshToken());

        return "redirect:/dashboard";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    private TokenResponse exchangeCodeForToken(String code) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("code", code);
        form.add("redirect_uri", redirectUri);

        return restClient
                .post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(TokenResponse.class);
    }

    private TokenResponse exchangeRefreshToken(String refreshToken) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);

        return restClient
                .post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(TokenResponse.class);
    }

    private String preview(String value) {
        if (value == null || value.isBlank()) {
            return "No disponible";
        }

        return value.substring(0, Math.min(value.length(), 80)) + "...";
    }
}