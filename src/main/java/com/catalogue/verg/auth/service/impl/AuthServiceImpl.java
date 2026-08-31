package com.catalogue.verg.auth.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.auth.service.AuthService;
import com.catalogue.verg.core.catalogue.service.CatalogueService;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.dto.RespParam;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.keycloak.service.KeycloakService;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class AuthServiceImpl implements AuthService {

    private static final String CLAIM_USER_ID = "user_id";
    private static final String CLAIM_USERNAME = "preferred_username";
    private static final String CLAIM_ORG_ID = "org_id";
    private static final String CLAIM_FUNCTIONAL_ROLE = "functional_role";
    private static final String CLAIM_ORG_NAME = "org_name";
    private static final String CLAIM_DISPLAY_NAME = "display_name";
    // Ours, not Keycloak's given_name/family_name: setup-realm.sh deletes the built-in profile
    // scope's two name mappers and oas-profile projects these instead.
    private static final String CLAIM_FIRST_NAME = "first_name";
    private static final String CLAIM_LAST_NAME = "last_name";
    private static final String CLAIM_SID = "sid";

    @Autowired
    private KeycloakService keycloakService;

    @Autowired
    private CatalogueService catalogueService;

    @Autowired
    private VergProperties vergProperties;

    /**
     * Issues tokens. Flag off (default) takes {@code {userId}} and trusts the caller; on takes
     * {@code {email, password}}. Never log the request (a password) or the result (the tokens).
     */
    @Override
    public CustomResponse authTokenCreate(JsonNode tokenDetails) {
        boolean verified = vergProperties.isCatalogueValidateEnabled();
        // Logged because the flag is otherwise silent: anything not read as true means false.
        log.info("AuthServiceImpl::authTokenCreate mode={}", verified ? "VERIFIED" : "TRUSTED");

        // Flag, not body shape: sniffing would let a caller downgrade by sending {userId}.
        String userId = verified
                ? catalogueService.verifyCredentials(
                        requiredText(tokenDetails, Constants.AUTH_FIELD_EMAIL),
                        requiredText(tokenDetails, Constants.AUTH_FIELD_PASSWORD))
                : requiredText(tokenDetails, Constants.AUTH_FIELD_USER_ID);

        Map<String, Object> tokens = keycloakService.requestToken(userId);
        indexSession(tokens);

        CustomResponse response = new CustomResponse();
        response.setResult(tokens);
        success(response);
        // The outcome names the path, so the audit shows whether the password was checked.
        audit("auth_token_create", userId, verified ? "SUCCESS" : "SUCCESS_UNVERIFIED",
                claimOf(tokens, CLAIM_FUNCTIONAL_ROLE));
        return response;
    }

    /**
     * Exchanges a refresh token for a fresh token pair, so a short access-token lifespan does not
     * force a re-login. Keycloak is the authority: the token is forwarded unexamined, because
     * verifyToken deliberately rejects a refresh token (typ != Bearer) and only Keycloak knows
     * whether the session behind it is still alive.
     */
    @Override
    public CustomResponse authTokenRefresh(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenRefresh");
        Map<String, Object> tokens = keycloakService.refreshToken(
                requiredText(tokenDetails, Constants.AUTH_FIELD_REFRESH_TOKEN));
        // A refresh keeps the sid and mints a new jti, so re-indexing extends the session record's
        // TTL and keeps "revoke this user" able to enumerate it.
        indexSession(tokens);

        CustomResponse response = new CustomResponse();
        response.setResult(tokens);
        success(response);
        audit("auth_token_refresh", claimOf(tokens, CLAIM_USER_ID), "SUCCESS",
                claimOf(tokens, CLAIM_FUNCTIONAL_ROLE));
        return response;
    }

    /**
     * Publishes a catalogue user into Keycloak when the record becomes ACTIVE. Idempotent, and the
     * re-enable path. Optional fields carry forward, so a republish that knows only the identifiers
     * never wipes a stored name — which also means a value set once cannot be unset here.
     */
    @Override
    public CustomResponse authUserCreate(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserCreate");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);
        // Required: without these, tokens carry a null org_id and tenant checks see "no org".
        String orgId = requiredText(userDetails, Constants.AUTH_FIELD_ORG_ID);
        String functionalRole = requiredText(userDetails, Constants.AUTH_FIELD_FUNCTIONAL_ROLE);
        // Also required: the email is the login identifier the catalogue verifies a password
        // against, so a user published without one could never authenticate.
        String email = requiredText(userDetails, Constants.AUTH_FIELD_EMAIL);
        String firstName = optionalText(userDetails, Constants.AUTH_FIELD_FIRST_NAME);
        String lastName = optionalText(userDetails, Constants.AUTH_FIELD_LAST_NAME);
        String orgName = optionalText(userDetails, Constants.AUTH_FIELD_ORG_NAME);
        String displayName = optionalText(userDetails, Constants.AUTH_FIELD_DISPLAY_NAME);

        boolean created = keycloakService.upsertUser(new KeycloakService.CatalogueUser(
                userId, orgId, functionalRole, email, firstName, lastName, orgName, displayName));

        CustomResponse response = new CustomResponse();
        Map<String, Object> result = new HashMap<>();
        result.put(Constants.AUTH_FIELD_USER_ID, userId);
        result.put("created", created);
        result.put("enabled", true);
        response.setResult(result);
        success(response);
        audit("auth_user_create", userId, created ? "USER_CREATED" : "USER_UPDATED", functionalRole);
        return response;
    }

    /**
     * Removes the user from Keycloak and kills every token they hold. Revocation runs FIRST: a
     * deleted user's already-signed JWTs stay valid, and once gone there are no sessions to
     * enumerate. A Redis failure must therefore stop the delete, not follow it.
     */
    @Override
    public CustomResponse authUserDelete(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserDelete");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);

        keycloakService.revokeUser(userId);
        boolean deleted = keycloakService.deleteUser(userId);

        CustomResponse response = new CustomResponse();
        Map<String, Object> result = new HashMap<>();
        result.put(Constants.AUTH_FIELD_USER_ID, userId);
        result.put("revoked", true);
        // Absent is success for an idempotent delete: a retried cleanup must be able to finish.
        result.put("deleted", deleted);
        response.setResult(result);
        success(response);
        audit("auth_user_delete", userId, deleted ? "USER_DELETED" : "USER_ABSENT", null);
        return response;
    }

    /** Verifies a token and returns a small claim summary. The token itself is never echoed back. */
    @Override
    public CustomResponse authTokenValidate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenValidate");
        DecodedJWT jwt = keycloakService.verifyToken(
                requiredText(tokenDetails, Constants.AUTH_FIELD_TOKEN), false);

        Map<String, Object> result = new HashMap<>();
        result.put("active", true);
        result.put("sub", jwt.getSubject());
        result.put(CLAIM_USERNAME, claim(jwt, CLAIM_USERNAME));
        result.put(CLAIM_USER_ID, claim(jwt, CLAIM_USER_ID));
        result.put(CLAIM_ORG_ID, claim(jwt, CLAIM_ORG_ID));
        result.put(CLAIM_ORG_NAME, claim(jwt, CLAIM_ORG_NAME));
        result.put(CLAIM_FUNCTIONAL_ROLE, claim(jwt, CLAIM_FUNCTIONAL_ROLE));
        result.put(CLAIM_DISPLAY_NAME, claim(jwt, CLAIM_DISPLAY_NAME));
        result.put(CLAIM_FIRST_NAME, claim(jwt, CLAIM_FIRST_NAME));
        result.put(CLAIM_LAST_NAME, claim(jwt, CLAIM_LAST_NAME));
        // From Keycloak's built-in email scope, not our mappers.
        result.put(Constants.AUTH_FIELD_EMAIL, claim(jwt, Constants.AUTH_FIELD_EMAIL));
        result.put("exp", jwt.getExpiresAt() == null ? null : jwt.getExpiresAt().toInstant().getEpochSecond());
        result.put("jti", jwt.getId());
        result.put(CLAIM_SID, claim(jwt, CLAIM_SID));

        CustomResponse response = new CustomResponse();
        response.setResult(result);
        success(response);
        return response;
    }

    /**
     * Revokes a token and ends its Keycloak session. Expiry is ignored: an expired token still
     * belongs to a session with live siblings. Verified before any write, so junk cannot fill Redis.
     */
    @Override
    public CustomResponse authTokenInvalidate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenInvalidate");
        DecodedJWT jwt = keycloakService.verifyToken(
                requiredText(tokenDetails, Constants.AUTH_FIELD_TOKEN), true);

        keycloakService.revokeToken(jwt);
        boolean idpLogout = keycloakService.logoutFromKeycloak(
                optionalText(tokenDetails, Constants.AUTH_FIELD_REFRESH_TOKEN));

        Map<String, Object> result = new HashMap<>();
        result.put("localRevocation", "ok");
        result.put("idpLogout", idpLogout ? "ok" : "failed");

        CustomResponse response = new CustomResponse();
        response.setResult(result);
        success(response);
        // Actor comes from the VERIFIED token, never the request body.
        String actor = StringUtils.defaultIfBlank(claim(jwt, CLAIM_USER_ID), claim(jwt, CLAIM_USERNAME));
        audit("auth_token_invalidate", actor, "REVOKED", claim(jwt, CLAIM_FUNCTIONAL_ROLE));
        return response;
    }

    /**
     * Blocks an account: kills every live token, then disables the user in Keycloak. Neither half
     * suffices — Redis stops a token already issued, the disable makes the block outlast the TTL.
     * Revocation throws; the disable is best-effort and reported in the body.
     */
    @Override
    public CustomResponse authUserRevoke(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserRevoke");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);

        keycloakService.revokeUser(userId);
        boolean disabled = keycloakService.disableUser(userId);

        Map<String, Object> result = new HashMap<>();
        result.put(Constants.AUTH_FIELD_USER_ID, userId);
        result.put("revoked", true);
        result.put("keycloakDisabled", disabled ? "ok" : "failed");

        CustomResponse response = new CustomResponse();
        response.setResult(result);
        success(response);
        audit("auth_user_revoke", userId, "USER_REVOKED", null);
        return response;
    }

    /** A missing field would NPE into a 500; this makes it a 400. */
    private String requiredText(JsonNode node, String field) {
        if (node == null || !node.hasNonNull(field) || StringUtils.isBlank(node.get(field).asText())) {
            throw new CustomException(Constants.AUTH_INVALID_REQUEST,
                    Constants.AUTH_INVALID_REQUEST_MSG, HttpStatus.BAD_REQUEST);
        }
        return node.get(field).asText();
    }

    private String optionalText(JsonNode node, String field) {
        return (node != null && node.hasNonNull(field)) ? node.get(field).asText() : null;
    }

    private String claim(DecodedJWT jwt, String name) {
        return jwt.getClaim(name).asString();
    }

    /** Records the freshly issued session. Safe to decode unverified: Keycloak just minted it. */
    private void indexSession(Map<String, Object> tokens) {
        try {
            Object accessToken = tokens == null ? null : tokens.get("access_token");
            if (accessToken != null) {
                keycloakService.recordSession(JWT.decode(accessToken.toString()));
            }
        } catch (Exception e) {
            log.warn("AuthServiceImpl::indexSession: could not index the session");
        }
    }

    /** Reads a claim from a freshly issued token, for the audit row only — never a decision. */
    private String claimOf(Map<String, Object> tokens, String claimName) {
        try {
            Object accessToken = tokens == null ? null : tokens.get("access_token");
            return accessToken == null ? null
                    : JWT.decode(accessToken.toString()).getClaim(claimName).asString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Audit trail, emitted to the application log the platform already collects; this service owns
     * no database. Logs only operation, actor and outcome — never a password, token or raw body.
     *
     * <p>The key is {@code functionalRole=}, renamed from {@code entityType=} with the claim. Any
     * log query or alert matching the old key needs updating with this release.
     */
    private void audit(String operation, String subject, String outcome, String functionalRole) {
        log.info("AUDIT operation={} userId={} functionalRole={} outcome={}",
                operation, subject, StringUtils.defaultString(functionalRole, "-"), outcome);
    }

    private void success(CustomResponse response) {
        response.setParams(new RespParam());
        response.getParams().setStatus(Constants.SUCCESS);
        response.setResponseCode(HttpStatus.OK);
    }
}
