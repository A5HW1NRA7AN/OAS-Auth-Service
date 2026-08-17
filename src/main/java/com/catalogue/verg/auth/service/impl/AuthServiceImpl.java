package com.catalogue.verg.auth.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.auth.service.AuthService;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.dto.RespParam;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.keycloak.service.KeycloakService;
import com.catalogue.verg.core.util.Constants;
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
    private static final String CLAIM_ENTITY_TYPE = "entity_type";

    @Autowired
    private KeycloakService keycloakService;

    /**
     * Issues tokens for a user that has already been authenticated elsewhere.
     *
     * <p>Never log the result — it contains the tokens.
     */
    @Override
    public CustomResponse authTokenCreate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenCreate");

        // ─── Credential verification: NOT YET WIRED ────────────────────────────────────────────
        // The user-catalogue will expose an endpoint that checks a username + password against its
        // own bcrypt hash and answers {valid, userId, orgId, entityType} — with an identical body
        // for unknown user, wrong password and non-ACTIVE, so nothing can be enumerated.
        //
        // When it exists, this method takes {username, password} again and:
        //   1. calls that endpoint first,
        //   2. maps valid:false             -> 401 AUTH_INVALID_CREDENTIALS,
        //   3. maps an unreachable catalogue -> 503 (fail closed; never issue a token),
        //   4. passes the RETURNED userId — not the submitted username — to requestToken(), so the
        //      catalogue can accept an email as the login identifier without a change here.
        //
        // Until then this endpoint TRUSTS ITS CALLER COMPLETELY: it mints a token for whatever
        // userId it is handed. It must never be routed through Kong or any ingress.
        // See README, "Credential verification".
        // ───────────────────────────────────────────────────────────────────────────────────────
        String userId = requiredText(tokenDetails, Constants.AUTH_FIELD_USER_ID);

        Map<String, Object> tokens = keycloakService.requestToken(userId);
        // Index the session so a later "disable this user" can find and kill it.
        indexSession(tokens);

        CustomResponse response = new CustomResponse();
        response.setResult(tokens);
        success(response);
        audit("auth_token_create", userId, "SUCCESS", entityTypeOf(tokens));
        return response;
    }

    /**
     * Publishes a catalogue user into Keycloak. Called when the record becomes ACTIVE.
     *
     * <p>Idempotent, and the same call re-enables a user that was previously revoked.
     */
    @Override
    public CustomResponse authUserCreate(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserCreate");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);
        // Required, not optional: a Keycloak user missing these mints tokens with a null org_id, and
        // every downstream tenant check then silently sees "no org".
        String orgId = requiredText(userDetails, Constants.AUTH_FIELD_ORG_ID);
        String entityType = requiredText(userDetails, Constants.AUTH_FIELD_ENTITY_TYPE);
        String email = optionalText(userDetails, Constants.AUTH_FIELD_EMAIL);

        boolean created = keycloakService.upsertUser(userId, orgId, entityType, email);

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
     * Removes the user from Keycloak and kills every token they are holding.
     *
     * <p>Revocation happens FIRST and is load-bearing: deleting a Keycloak user does not invalidate a
     * JWT it already signed, and once the user is gone there is nothing left to enumerate sessions
     * for. So a Redis failure must stop the delete, not follow it.
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
        // Absent in Keycloak is a success for an idempotent delete, not a 404: a caller retrying a
        // half-finished cleanup must be able to complete it.
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
        result.put("exp", jwt.getExpiresAt() == null ? null : jwt.getExpiresAt().toInstant().getEpochSecond());
        result.put("jti", jwt.getId());
        result.put("sid", claim(jwt, "sid"));

        CustomResponse response = new CustomResponse();
        response.setResult(result);
        success(response);
        return response;
    }

    /**
     * Revokes a token and ends its Keycloak session.
     *
     * <p>Expiry is ignored while verifying, because an expired access token still belongs to a
     * session whose newer tokens are live. The token is verified before anything is written, so
     * an unverified token cannot be used to fill Redis with junk.
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
     * Blocks an account: kills every live token, then disables the user in Keycloak.
     *
     * <p>Both halves are needed and neither is sufficient. The Redis revocation is what stops a user
     * who is already holding a valid access token — Keycloak cannot recall one it has issued. The
     * Keycloak disable is what makes the block outlast the denylist TTL, since otherwise the account
     * would quietly start working again once those entries expired.
     *
     * <p>Revocation is load-bearing and throws; the disable is best-effort and reported in the body.
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

    /**
     * {@code node.get("password").asText()} throws NPE when the field is absent, surfacing as a
     * confusing 500. This turns it into a 400.
     */
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
     * Audit trail. Emitted to the application log, which the platform already collects — this
     * service owns no database, and the `audit` catalogue belongs to agri-catalogue-service.
     *
     * <p>Deliberately logs only the operation, who did it and the outcome. Never the password, the
     * token, or the raw request body.
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
