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
     * The catalogue's view of a user, as pushed into Keycloak. A record rather than the eight
     * positional arguments it replaces: with six of them consecutive Strings, transposing any two
     * compiles cleanly and no test can see it.
     *
     * <p>Not a DTO in the sense AUTH_SERVICE.md rules out — it mirrors no wire format and no
     * Keycloak response, and exists only to name these arguments.
     *
     * <p>{@code userId}, {@code orgId}, {@code functionalRole} and {@code email} are required; the
     * rest are optional and CARRY FORWARD when null. {@code functionalRole} was {@code entityType}
     * until the catalogue collapsed its per-catalogue {@code registry[]} to a single role.
     */
    record CatalogueUser(String userId, String orgId, String functionalRole, String email,
                         String firstName, String lastName, String orgName, String displayName) {
    }

    /**
     * Creates or updates the Keycloak user, with no credential. Also the re-enable path.
     *
     * <p>Every optional field carries forward: a null leaves whatever is stored alone, so a
     * republish that knows only the identifiers never wipes a name. There is deliberately no
     * "clear" signal — an attribute set once cannot be unset through this endpoint, because the
     * caller retries this call and a stray null must not erase a value it did not mean to touch.
     *
     * @return true when a user was created, false when an existing one was updated
     */
    boolean upsertUser(CatalogueUser user);

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
