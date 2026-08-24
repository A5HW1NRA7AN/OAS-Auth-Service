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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class AuthServiceImpl implements AuthService {

    private static final String CLAIM_USER_ID = "user_id";
    private static final String CLAIM_USERNAME = "preferred_username";
    private static final String CLAIM_ENTITY_TYPE = "entity_type";

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
                entityTypeOf(tokens));
        return response;
    }

    /**
     * Publishes a catalogue user into Keycloak when the record becomes ACTIVE. Idempotent, and the
     * re-enable path. Optional fields carry forward; registries is three-state (absent keeps,
     * {@code []} clears, non-empty replaces).
     */
    @Override
    public CustomResponse authUserCreate(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserCreate");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);
        // Required: without these, tokens carry a null org_id and tenant checks see "no org".
        String orgId = requiredText(userDetails, Constants.AUTH_FIELD_ORG_ID);
        String entityType = requiredText(userDetails, Constants.AUTH_FIELD_ENTITY_TYPE);
        String email = optionalText(userDetails, Constants.AUTH_FIELD_EMAIL);
        String firstName = optionalText(userDetails, Constants.AUTH_FIELD_FIRST_NAME);
        String lastName = optionalText(userDetails, Constants.AUTH_FIELD_LAST_NAME);
        List<String> registries = optionalStrings(userDetails, Constants.AUTH_FIELD_REGISTRIES);

        boolean created = keycloakService.upsertUser(userId, orgId, entityType, email,
                firstName, lastName, registries);

        CustomResponse response = new CustomResponse();
        Map<String, Object> result = new HashMap<>();
        result.put(Constants.AUTH_FIELD_USER_ID, userId);
        result.put("created", created);
        result.put("enabled", true);
        response.setResult(result);
        success(response);
        audit("auth_user_create", userId, created ? "USER_CREATED" : "USER_UPDATED", entityType);
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
        result.put("preferred_username", claim(jwt, CLAIM_USERNAME));
        result.put("user_id", claim(jwt, CLAIM_USER_ID));
        result.put("org_id", claim(jwt, "org_id"));
        result.put("entity_type", claim(jwt, CLAIM_ENTITY_TYPE));
        // From Keycloak's built-in profile/email scopes, not our mappers.
        result.put("given_name", claim(jwt, "given_name"));
        result.put("family_name", claim(jwt, "family_name"));
        result.put("email", claim(jwt, Constants.AUTH_FIELD_EMAIL));
        result.put("registries", claimList(jwt, Constants.AUTH_FIELD_REGISTRIES));
        result.put("exp", jwt.getExpiresAt() == null ? null : jwt.getExpiresAt().toInstant().getEpochSecond());
        result.put("jti", jwt.getId());
        result.put("sid", claim(jwt, "sid"));

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
        audit("auth_token_invalidate", actor, "REVOKED", claim(jwt, CLAIM_ENTITY_TYPE));
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

    /** Optional string array; null keeps, [] clears. Blanks/dupes dropped; a non-array is a 400. */
    private List<String> optionalStrings(JsonNode node, String field) {
        if (node == null || !node.hasNonNull(field)) {
            return null;
        }
        JsonNode array = node.get(field);
        if (!array.isArray()) {
            throw new CustomException(Constants.AUTH_INVALID_REQUEST,
                    Constants.AUTH_INVALID_REQUEST_MSG, HttpStatus.BAD_REQUEST);
        }
        List<String> values = new ArrayList<>();
        for (JsonNode value : array) {
            String text = value.asText().trim();
            if (StringUtils.isNotBlank(text) && !values.contains(text)) {
                values.add(text);
            }
        }
        return values;
    }

    private String claim(DecodedJWT jwt, String name) {
        return jwt.getClaim(name).asString();
    }

    /** Multi-valued claim. Null when absent — Keycloak omits an empty attribute, so never {@code []}. */
    private List<String> claimList(DecodedJWT jwt, String name) {
        return jwt.getClaim(name).asList(String.class);
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

    /** Reads entity_type from a freshly issued token, for the audit row only — never a decision. */
    private String entityTypeOf(Map<String, Object> tokens) {
        try {
            Object accessToken = tokens == null ? null : tokens.get("access_token");
            return accessToken == null ? null
                    : JWT.decode(accessToken.toString()).getClaim(CLAIM_ENTITY_TYPE).asString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Audit trail, emitted to the application log the platform already collects; this service owns
     * no database. Logs only operation, actor and outcome — never a password, token or raw body.
     */
    private void audit(String operation, String subject, String outcome, String entityType) {
        log.info("AUDIT operation={} userId={} entityType={} outcome={}",
                operation, subject, StringUtils.defaultString(entityType, "-"), outcome);
    }

    private void success(CustomResponse response) {
        response.setParams(new RespParam());
        response.getParams().setStatus(Constants.SUCCESS);
        response.setResponseCode(HttpStatus.OK);
    }
}
