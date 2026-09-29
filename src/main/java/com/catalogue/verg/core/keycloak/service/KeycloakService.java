package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

/** Tokens, PIN devices and Keycloak users, keyed by catalogue userId; Redis makes revocation stick. */
public interface KeycloakService {

    /** Issues tokens with no password (the direct grant checks nothing): TRUSTS ITS CALLER. */
    Map<String, Object> requestToken(String userId);

    /** Verifies and decodes a token; ignoreExpiry lets invalidate kill an expired token's session. */
    DecodedJWT verifyToken(String token, boolean ignoreExpiry);

    /** Indexes a session so it can be found and killed later. Best-effort. */
    void recordSession(DecodedJWT jwt);

    /** Denylists one token and its session. */
    void revokeToken(DecodedJWT jwt);

    /** Revokes every live token and PIN device for a user — what blocking an account requires. */
    void revokeUser(String userId);

    /** Returned once on enrolment; only the handle's SHA-256 is stored. */
    record DeviceEnrolment(String deviceHandle, String deviceId) {
    }

    /** How the PIN check behind a claimed attempt ended. */
    enum PinAttempt {
        CORRECT,
        WRONG,
        /** The catalogue could not answer; says nothing about the PIN. */
        UNCHECKED
    }

    /** Enrols a device for a user whose password was just verified; 503 if Redis cannot store it. */
    DeviceEnrolment enrolDevice(String userId, String label);

    /** Spends one of five PIN attempts before the check and returns the device's userId; fails closed. */
    String claimPinAttempt(String deviceHandle);

    /** Settles a claimed attempt without throwing; true when the device was just removed. */
    boolean settlePinAttempt(String deviceHandle, PinAttempt outcome);

    /** Ends the Keycloak session and refresh token. Returns false on failure rather than throwing. */
    boolean logoutFromKeycloak(String refreshToken);

    /** Exchanges a refresh token for a new pair; 401 when Keycloak refuses it, 503 when unreachable. */
    Map<String, Object> refreshToken(String refreshToken);

    /** The catalogue's user as pushed to Keycloak; a record so six String arguments cannot transpose. */
    record CatalogueUser(String userId, String orgId, String functionalRole, String email,
                         String firstName, String lastName, String orgName, String displayName) {
    }

    /** Creates or updates the user (no credential); nulls carry forward, it re-enables; true if created. */
    boolean upsertUser(CatalogueUser user);

    /** Replaces the profile (omitted fields clear) without re-enabling the user; 404 if absent. */
    void replaceUser(CatalogueUser user);

    /** Disables the user and ends their sessions; false if Keycloak fails, 404 if there is no such user. */
    boolean disableUser(String userId);

    /** Deletes the Keycloak user; false when absent, which counts as success. */
    boolean deleteUser(String userId);
}
