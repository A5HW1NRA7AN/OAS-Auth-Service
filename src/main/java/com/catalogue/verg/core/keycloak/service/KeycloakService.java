package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

/**
 * Obtains, verifies and revokes tokens.
 *
 * <p>Tokens are verified locally against Keycloak's published signing key rather than by calling
 * Keycloak on every request. Keycloak cannot cancel an access token it has already issued, so the
 * Redis denylist is what actually makes revocation work; the Keycloak logout call only ends the
 * session and refresh token.
 */
public interface KeycloakService {

    /** Exchanges credentials for tokens. Keycloak delegates the password check to the catalogue. */
    Map<String, Object> requestToken(String username, String password);

    /**
     * Verifies a token and returns it decoded.
     *
     * @param ignoreExpiry needed by invalidate, which must accept an already-expired token so the
     *                     rest of its session can still be killed.
     */
    DecodedJWT verifyToken(String token, boolean ignoreExpiry);

    /** Indexes a session so it can be found and killed later. Best-effort. */
    void recordSession(DecodedJWT jwt);

    /** Denylists one token and its session. */
    void revokeToken(DecodedJWT jwt);

    /** Revokes every live token for a user — what blocking an account requires. */
    void revokeUser(String userId);

    /** Ends the Keycloak session and refresh token. Returns false on failure rather than throwing. */
    boolean logoutFromKeycloak(String refreshToken);
}
