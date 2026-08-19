package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

/**
 * Issues, verifies and revokes tokens, and administers the Keycloak users those tokens are for.
 *
 * <p>Tokens are verified locally against Keycloak's published signing key rather than by calling
 * Keycloak on every request. Keycloak cannot cancel an access token it has already issued, so the
 * Redis denylist is what actually makes revocation work; the Keycloak logout call only ends the
 * session and refresh token.
 *
 * <p>The user-administration methods speak the catalogue's {@code userId} throughout — it is the
 * Keycloak username — so no caller ever handles a Keycloak internal id.
 */
public interface KeycloakService {

    /**
     * Issues tokens for a user Keycloak holds no credential for.
     *
     * <p>Takes no password: the realm's direct grant flow performs no credential check, so this
     * TRUSTS ITS CALLER. Verifying the password is the caller's responsibility, upstream of here.
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
     * Creates or updates the Keycloak user, with no credential. Also the re-enable path.
     *
     * <p>Optional fields are carried forward when omitted. {@code registries} is three-state: null
     * keeps, empty clears, non-empty replaces — so a caller that owns the list must always send it.
     *
     * @return true when a user was created, false when an existing one was updated
     */
    boolean upsertUser(String userId, String orgId, String entityType, String email,
                       String firstName, String lastName, java.util.List<String> registries);

    /**
     * Disables the user and ends their Keycloak sessions.
     *
     * @return false if it could not be done — best-effort, because the Redis revocation is what
     *         stops a blocked user already holding a token
     */
    boolean disableUser(String userId);

    /**
     * Deletes the Keycloak user.
     *
     * @return false when there was no such user, which is a success for an idempotent delete
     */
    boolean deleteUser(String userId);
}
