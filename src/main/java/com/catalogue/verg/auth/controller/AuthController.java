package com.catalogue.verg.auth.controller;

import com.catalogue.verg.auth.service.AuthService;
import com.catalogue.verg.core.dto.CustomResponse;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The auth-service API.
 *
 * <p>Every endpoint here is intended for service-to-service use and none of them authenticate their
 * caller. They must not be routed through Kong or any ingress — see the README. That matters most for
 * {@code auth_token_create}, which currently mints a token for whatever userId it is given.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    /** userId -> tokens. Verifying the password is the caller's job; see AuthServiceImpl. */
    @PostMapping("/v1/auth_token_create")
    public ResponseEntity<CustomResponse> authTokenCreate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenCreate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /** Verifies a token locally and returns a summary of its claims. */
    @PostMapping("/v1/auth_token_validate")
    public ResponseEntity<CustomResponse> authTokenValidate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenValidate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /** Revokes one token and ends its Keycloak session. */
    @PostMapping("/v1/auth_token_invalidate")
    public ResponseEntity<CustomResponse> authTokenInvalidate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenInvalidate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /**
     * Publishes a catalogue user into Keycloak, so tokens can be issued for them. Called when the
     * record becomes ACTIVE. Idempotent, and the same call re-enables a revoked user.
     */
    @PostMapping("/v1/auth_user_create")
    public ResponseEntity<CustomResponse> authUserCreate(@RequestBody JsonNode userDetails) {
        CustomResponse response = authService.authUserCreate(userDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /**
     * Blocks an account: kills every live token and disables the user in Keycloak. Called on
     * ACTIVE -> INACTIVE. Disabling alone would only stop the next login.
     */
    @PostMapping("/v1/auth_user_revoke")
    public ResponseEntity<CustomResponse> authUserRevoke(@RequestBody JsonNode userDetails) {
        CustomResponse response = authService.authUserRevoke(userDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /** Removes the user from Keycloak and kills every token they hold. Called on delete. */
    @PostMapping("/v1/auth_user_delete")
    public ResponseEntity<CustomResponse> authUserDelete(@RequestBody JsonNode userDetails) {
        CustomResponse response = authService.authUserDelete(userDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }
}
