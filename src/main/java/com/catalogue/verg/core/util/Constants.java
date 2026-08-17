package com.catalogue.verg.core.util;

/**
 * Request field names and the client-facing error codes.
 *
 * <p>The messages are fixed strings. They never carry the underlying exception text and never
 * Keycloak's own error_description — those leak internal hostnames, and in the credential case they
 * would distinguish "no such user" from "wrong password" from "account disabled", which lets someone
 * enumerate valid usernames and learn that their guessing is working.
 */
public final class Constants {

    private Constants() {
    }

    public static final String SUCCESS = "success";

    // Token endpoint request fields
    public static final String AUTH_FIELD_USERNAME = "username";
    public static final String AUTH_FIELD_PASSWORD = "password";
    public static final String AUTH_FIELD_TOKEN = "token";
    public static final String AUTH_FIELD_REFRESH_TOKEN = "refreshToken";
    public static final String AUTH_FIELD_USER_ID = "userId";

    public static final String AUTH_INVALID_REQUEST = "AUTH_INVALID_REQUEST";
    public static final String AUTH_INVALID_REQUEST_MSG = "Request is missing a required field";

    /** Deliberately identical for wrong password, unknown user and disabled account. */
    public static final String AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS";
    public static final String AUTH_INVALID_CREDENTIALS_MSG = "Invalid credentials";

    public static final String AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID";
    public static final String AUTH_TOKEN_INVALID_MSG = "Token is not valid";

    public static final String AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED";
    public static final String AUTH_TOKEN_EXPIRED_MSG = "Token has expired";

    public static final String AUTH_TOKEN_REVOKED = "AUTH_TOKEN_REVOKED";
    public static final String AUTH_TOKEN_REVOKED_MSG = "Token has been revoked";

    public static final String AUTH_UPSTREAM_UNAVAILABLE = "AUTH_UPSTREAM_UNAVAILABLE";
    public static final String AUTH_UPSTREAM_UNAVAILABLE_MSG = "Authentication service is unavailable";

    public static final String AUTH_REVOCATION_FAILED = "AUTH_REVOCATION_FAILED";
    public static final String AUTH_REVOCATION_FAILED_MSG = "Unable to complete revocation";
}
