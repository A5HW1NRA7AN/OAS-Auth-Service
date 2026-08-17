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
     * Exchanges credentials for tokens.
     *
     * <p>Never log {@code tokenDetails} here — it contains the plaintext password.
     */
    @Override
    public CustomResponse authTokenCreate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenCreate");
        String username = requiredText(tokenDetails, Constants.AUTH_FIELD_USERNAME);
        String password = requiredText(tokenDetails, Constants.AUTH_FIELD_PASSWORD);

        Map<String, Object> tokens = keycloakService.requestToken(username, password);
        // Index the session so a later "disable this user" can find and kill it.
        indexSession(tokens);

        CustomResponse response = new CustomResponse();
        response.setResult(tokens);
        success(response);
        audit("auth_token_create", username, "SUCCESS", entityTypeOf(tokens));
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

    /** Revokes every live token for a user. Used when an account is blocked. */
    @Override
    public CustomResponse authUserRevoke(JsonNode userDetails) {
        log.info("AuthServiceImpl::authUserRevoke");
        String userId = requiredText(userDetails, Constants.AUTH_FIELD_USER_ID);

        keycloakService.revokeUser(userId);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", userId);
        result.put("revoked", true);

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
