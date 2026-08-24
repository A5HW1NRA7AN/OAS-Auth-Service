package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

/**
 * Issues, verifies and revokes tokens, and administers the Keycloak users behind them.
 *
 * <p>Tokens are verified locally against the published signing key, not by calling Keycloak per
 * request. Keycloak cannot cancel a token it already issued, so the Redis denylist is what makes
 * revocation work; its logout only ends the session and refresh token.
 *
 * <p>Every method speaks the catalogue's {@code userId} — the Keycloak username — so no caller
 * handles a Keycloak internal id.
 */
public interface KeycloakService {

    /**
     * Issues tokens for a user Keycloak holds no credential for. Takes no password: the direct
     * grant flow checks nothing, so this TRUSTS ITS CALLER. Verification happens upstream.
     */
    Map<String, Object> requestToken(String userId);

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

    /**
     * Creates or updates the Keycloak user, with no credential. Also the re-enable path. Optional
     * fields carry forward; {@code registries} is three-state (null keeps, empty clears, non-empty
     * replaces), so a caller owning the list must always send it.
     *
     * @return true when a user was created, false when an existing one was updated
     */
    boolean upsertUser(String userId, String orgId, String entityType, String email,
                       String firstName, String lastName, java.util.List<String> registries);

    /**
     * Disables the user and ends their Keycloak sessions.
     *
     * @return false if Keycloak could not be reached; best-effort, since Redis already stopped them
     * @throws com.catalogue.verg.core.exception.CustomException 404 when there is no such user —
     *         nothing was revoked, so a wrong identifier must not look like success
     */
    boolean disableUser(String userId);

    /**
     * Deletes the Keycloak user.
     *
     * @return false when there was no such user, which is a success for an idempotent delete
     */
    boolean deleteUser(String userId);
}
