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
 * The auth-service API, for service-to-service use. Only {@code auth_token_create} checks a
 * credential (and only while {@code catalogue.validate-enabled} is on); the {@code auth_user_*}
 * endpoints authenticate no caller at all, so they must not be reachable from an ingress —
 * see the README.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    /** {email, password} -> tokens, the password verified by the user-catalogue. Falls back to
     *  {userId} on trust when {@code catalogue.validate-enabled} is off; see AuthServiceImpl. */
    @PostMapping("/v1/auth_token_create")
    public ResponseEntity<CustomResponse> authTokenCreate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenCreate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /** {refreshToken} -> a fresh token pair, so a short access-token lifespan is not a re-login. */
    @PostMapping("/v1/auth_token_refresh")
    public ResponseEntity<CustomResponse> authTokenRefresh(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenRefresh(tokenDetails);
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

    /** Publishes a catalogue user into Keycloak on ACTIVE. Idempotent; also re-enables. */
    @PostMapping("/v1/auth_user_create")
    public ResponseEntity<CustomResponse> authUserCreate(@RequestBody JsonNode userDetails) {
        CustomResponse response = authService.authUserCreate(userDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    /** Blocks an account on ACTIVE -> INACTIVE. Disabling alone would only stop the next login. */
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
