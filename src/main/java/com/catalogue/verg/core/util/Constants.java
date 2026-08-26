package com.catalogue.verg.core.util;

/**
 * Request field names and client-facing error codes.
 *
 * <p>Messages are fixed strings, never the underlying exception or Keycloak's error_description:
 * those leak internal hostnames and would let a caller tell "no such user" from "wrong password".
 */
public final class Constants {

    private Constants() {
    }

    public static final String SUCCESS = "success";

    // Request fields, camelCase to match the user catalogue's payload; the claims they become are
    // snake_case. Only auth_token_create takes a credential, and only when
    // catalogue.validate-enabled is true. The login identifier is the email.
    public static final String AUTH_FIELD_PASSWORD = "password";
    public static final String AUTH_FIELD_TOKEN = "token";
    public static final String AUTH_FIELD_REFRESH_TOKEN = "refreshToken";
    public static final String AUTH_FIELD_USER_ID = "userId";
    public static final String AUTH_FIELD_ORG_ID = "orgId";
    /** Renamed from entityType when the catalogue collapsed its per-catalogue registry[] to one role. */
    public static final String AUTH_FIELD_FUNCTIONAL_ROLE = "functionalRole";
    public static final String AUTH_FIELD_EMAIL = "email";
    public static final String AUTH_FIELD_FIRST_NAME = "firstName";
    public static final String AUTH_FIELD_LAST_NAME = "lastName";
    public static final String AUTH_FIELD_ORG_NAME = "orgName";
    public static final String AUTH_FIELD_DISPLAY_NAME = "displayName";

    public static final String AUTH_INVALID_REQUEST = "AUTH_INVALID_REQUEST";
    public static final String AUTH_INVALID_REQUEST_MSG = "Request is missing a required field";

    /** Deliberately identical for a wrong password, an unknown user and a non-ACTIVE account. */
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

    /** The publish never reached us — the caller should call auth_user_create. */
    public static final String AUTH_USER_NOT_FOUND = "AUTH_USER_NOT_FOUND";
    public static final String AUTH_USER_NOT_FOUND_MSG = "User is not provisioned in the identity provider";

    /** Blocked in the identity provider. auth_user_create re-enables. */
    public static final String AUTH_USER_DISABLED = "AUTH_USER_DISABLED";
    public static final String AUTH_USER_DISABLED_MSG = "User is disabled in the identity provider";

    /** A different identity already holds these details, so retrying will not help. */
    public static final String AUTH_USER_CONFLICT = "AUTH_USER_CONFLICT";
    public static final String AUTH_USER_CONFLICT_MSG = "Another user already holds these details";

    /** Configuration problem rather than a transient one — alert, do not retry in a loop. */
    public static final String AUTH_IDP_OPERATION_FAILED = "AUTH_IDP_OPERATION_FAILED";
    public static final String AUTH_IDP_OPERATION_FAILED_MSG = "Identity provider rejected the request";
}
