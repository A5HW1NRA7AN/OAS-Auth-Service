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

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    /** Credentials -> tokens. The password is verified by the user-catalogue, not by Keycloak. */
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
     * Revokes every live token for a user. Called when an account is blocked: disabling the user
     * upstream only stops the next login, tokens already issued keep working until they expire.
     */
    @PostMapping("/v1/auth_user_revoke")
    public ResponseEntity<CustomResponse> authUserRevoke(@RequestBody JsonNode userDetails) {
        CustomResponse response = authService.authUserRevoke(userDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }
}
