package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class KeycloakServiceImpl implements KeycloakService {

    private static final String CLAIM_TYP = "typ";
    private static final String CLAIM_AZP = "azp";
    private static final String CLAIM_SID = "sid";
    private static final String CLAIM_USER_ID = "user_id";
    private static final String CLAIM_ORG_ID = "org_id";
    private static final String CLAIM_ENTITY_TYPE = "entity_type";
    private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
    private static final String TOKEN_TYPE_BEARER = "Bearer";

    private static final String DENYLIST_JTI_PREFIX = "auth:denylist:jti:";
    private static final String DENYLIST_SID_PREFIX = "auth:denylist:sid:";
    private static final String DENYLIST_USER_PREFIX = "auth:denylist:user:";
    private static final String DENYLIST_VALUE = "1";

    // Session index. Not part of the security decision — validation stays signature + claims +
    // denylist — but it is what lets "disable this user" enumerate and clear every live session
    // instead of hoping one TTL covers every outstanding token.
    private static final String SESSION_PREFIX = "auth:session:";
    private static final String USER_SESSIONS_PREFIX = "auth:user:";
    private static final String USER_SESSIONS_SUFFIX = ":sessions";

    private static final long ADMIN_TOKEN_SKEW_SECONDS = 30;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Object adminTokenLock = new Object();
    private volatile String adminAccessToken;
    private volatile Instant adminAccessTokenExpiresAt = Instant.EPOCH;

    @Autowired
    private VergProperties vergProperties;

    @Autowired
    @Qualifier("keycloakRestTemplate")
    private RestTemplate restTemplate;

    @Autowired
    private JwkProvider jwkProvider;

    /**
     * Injected directly rather than through a cache helper: a cache may swallow Redis errors, which
     * is right for a cache and wrong for a denylist.
     */
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> requestToken(String userId) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", vergProperties.getKeycloakClientId());
        form.add("username", userId);
        if (StringUtils.isNotBlank(vergProperties.getKeycloakClientSecret())) {
            form.add("client_secret", vergProperties.getKeycloakClientSecret());
        }
        // No password field, deliberately. The realm's direct grant flow contains only
        // direct-grant-validate-username, so Keycloak resolves the user, enforces the `enabled`
        // flag and issues the token without looking for a credential it does not hold.
        // setup-realm.sh step 4 is the other half of this; the two must stay in step.

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    tokenEndpoint(), HttpMethod.POST, formEntity(form), Map.class);
            return response.getBody();
        } catch (HttpClientErrorException e) {
            log.warn("KeycloakServiceImpl::requestToken: grant refused for {} (status={})",
                    userId, e.getStatusCode());
            throw explainRefusedGrant(userId);
        } catch (RestClientException e) {
            // Never surface the cause: it leaks the internal hostname and port.
            log.error("KeycloakServiceImpl::requestToken: Keycloak unreachable", e);
            throw unreachable();
        }
    }

    /**
     * Keycloak answers a bare {@code invalid_grant} for both an unknown and a disabled user. There is
     * no password in play here, so there is nothing to enumerate — one admin lookup on the failure
     * path turns that into a diagnosis the caller can act on.
     */
    private CustomException explainRefusedGrant(String userId) {
        JsonNode user;
        try {
            user = findUser(userId);
        } catch (Exception e) {
            return unreachable();
        }
        if (user == null) {
            log.warn("KeycloakServiceImpl::requestToken: {} is not provisioned in Keycloak", userId);
            return new CustomException(Constants.AUTH_USER_NOT_FOUND,
                    Constants.AUTH_USER_NOT_FOUND_MSG, HttpStatus.NOT_FOUND);
        }
        if (!user.path("enabled").asBoolean(false)) {
            return new CustomException(Constants.AUTH_USER_DISABLED,
                    Constants.AUTH_USER_DISABLED_MSG, HttpStatus.FORBIDDEN);
        }
        log.error("KeycloakServiceImpl::requestToken: grant refused for an ENABLED user {} — "
                + "check the realm's direct grant flow", userId);
        return idpFailed();
    }

    @Override
    public DecodedJWT verifyToken(String token, boolean ignoreExpiry) {
        if (StringUtils.isBlank(token)) {
            throw new CustomException(Constants.AUTH_INVALID_REQUEST,
                    Constants.AUTH_INVALID_REQUEST_MSG, HttpStatus.BAD_REQUEST);
        }

        DecodedJWT decoded;
        try {
            decoded = JWT.decode(token);
        } catch (Exception e) {
            throw invalidToken("not a well-formed JWT");
        }

        // The algorithm is pinned to RS256 and never read from the token header. Keycloak's public
        // key is published openly; trusting the header lets an attacker sign a forged token with
        // that public key as an HMAC secret, set alg=HS256, and pass verification.
        try {
            Jwk jwk = jwkProvider.get(decoded.getKeyId());
            Algorithm.RSA256((java.security.interfaces.RSAPublicKey) jwk.getPublicKey(), null).verify(decoded);
        } catch (CustomException e) {
            throw e;
        } catch (Exception e) {
            throw invalidToken("signature verification failed");
        }

        if (!vergProperties.getKeycloakIssuer().equals(decoded.getIssuer())) {
            throw invalidToken("issuer mismatch");
        }

        if (!ignoreExpiry) {
            Instant now = Instant.now();
            long skew = vergProperties.getKeycloakClockSkewSeconds();
            Date exp = decoded.getExpiresAt();
            if (exp != null && exp.toInstant().plusSeconds(skew).isBefore(now)) {
                throw new CustomException(Constants.AUTH_TOKEN_EXPIRED,
                        Constants.AUTH_TOKEN_EXPIRED_MSG, HttpStatus.UNAUTHORIZED);
            }
            Date nbf = decoded.getNotBefore();
            if (nbf != null && nbf.toInstant().minusSeconds(skew).isAfter(now)) {
                throw invalidToken("token not valid yet");
            }
        }

        // Refresh tokens are signed with the same key and pass every check above. Without this,
        // sending a refresh token to validate returns 200.
        if (!TOKEN_TYPE_BEARER.equals(decoded.getClaim(CLAIM_TYP).asString())) {
            throw invalidToken("expected typ=Bearer");
        }

        // Realms are shared: without this, a token issued to another client would be accepted.
        if (!vergProperties.getKeycloakClientId().equals(decoded.getClaim(CLAIM_AZP).asString())) {
            throw invalidToken("azp is not this client");
        }

        // The denylist keys on jti, so a token without one could never be revoked.
        if (StringUtils.isBlank(decoded.getId())) {
            throw invalidToken("missing jti");
        }

        if (isRevoked(decoded)) {
            throw new CustomException(Constants.AUTH_TOKEN_REVOKED,
                    Constants.AUTH_TOKEN_REVOKED_MSG, HttpStatus.UNAUTHORIZED);
        }

        return decoded;
    }

    @Override
    public void recordSession(DecodedJWT jwt) {
        String sid = jwt.getClaim(CLAIM_SID).asString();
        String userId = resolveUserId(jwt);
        if (StringUtils.isBlank(sid) || StringUtils.isBlank(userId)) {
            return;
        }
        try {
            long ttl = vergProperties.getKeycloakDenylistSidTtlSeconds();
            String session = String.format(
                    "{\"user_id\":\"%s\",\"org_id\":\"%s\",\"entity_type\":\"%s\",\"username\":\"%s\"}",
                    userId,
                    StringUtils.defaultString(jwt.getClaim(CLAIM_ORG_ID).asString()),
                    StringUtils.defaultString(jwt.getClaim(CLAIM_ENTITY_TYPE).asString()),
                    StringUtils.defaultString(jwt.getClaim(CLAIM_PREFERRED_USERNAME).asString()));

            stringRedisTemplate.opsForValue().set(SESSION_PREFIX + sid, session, ttl, TimeUnit.SECONDS);
            String indexKey = userSessionsKey(userId);
            stringRedisTemplate.opsForSet().add(indexKey, sid);
            stringRedisTemplate.expire(indexKey, ttl, TimeUnit.SECONDS);
        } catch (Exception e) {
            // A login must not fail because the index could not be written; the token is already
            // valid and the denylist still governs revocation.
            log.warn("KeycloakServiceImpl::recordSession: could not index session for {}", userId);
        }
    }

    /**
     * Denylists one token and its session.
     *
     * <p>Both entries are needed: {@code jti} is this token, {@code sid} is the session, and every
     * refresh mints a new token — revoking only the jti leaves its siblings working.
     *
     * <p>Values are a constant "1", never the token itself — a Redis dump should never hand anyone
     * a usable credential.
     */
    @Override
    public void revokeToken(DecodedJWT jwt) {
        try {
            long sidTtl = vergProperties.getKeycloakDenylistSidTtlSeconds();
            Date exp = jwt.getExpiresAt();
            long ttl = exp == null ? sidTtl : Duration.between(Instant.now(), exp.toInstant()).getSeconds();

            if (ttl > 0) {
                stringRedisTemplate.opsForValue()
                        .set(DENYLIST_JTI_PREFIX + jwt.getId(), DENYLIST_VALUE, ttl, TimeUnit.SECONDS);
            }
            String sid = jwt.getClaim(CLAIM_SID).asString();
            String userId = resolveUserId(jwt);
            if (StringUtils.isNotBlank(sid)) {
                stringRedisTemplate.opsForValue()
                        .set(DENYLIST_SID_PREFIX + sid, DENYLIST_VALUE, sidTtl, TimeUnit.SECONDS);
                stringRedisTemplate.delete(SESSION_PREFIX + sid);
                if (StringUtils.isNotBlank(userId)) {
                    stringRedisTemplate.opsForSet().remove(userSessionsKey(userId), sid);
                }
            }
            log.info("KeycloakServiceImpl::revokeToken: revoked jti={}", jwt.getId());
        } catch (Exception e) {
            log.error("KeycloakServiceImpl::revokeToken: Redis write failed — token NOT revoked", e);
            throw new CustomException(Constants.AUTH_REVOCATION_FAILED,
                    Constants.AUTH_REVOCATION_FAILED_MSG, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Revokes every live token for a user, which is what blocking an account requires — disabling
     * the user upstream only stops the next login.
     *
     * <p>Keyed on {@code user_id} rather than {@code sub}, so callers can use the catalogue id they
     * already hold.
     */
    @Override
    public void revokeUser(String userId) {
        try {
            long ttl = vergProperties.getKeycloakDenylistSidTtlSeconds();
            stringRedisTemplate.opsForValue()
                    .set(DENYLIST_USER_PREFIX + userId, DENYLIST_VALUE, ttl, TimeUnit.SECONDS);

            // Clear every live session rather than relying on the user-level entry alone: each
            // session is denylisted by sid and its record deleted, so nothing survives even if the
            // user key later expires.
            String indexKey = userSessionsKey(userId);
            Set<String> sids = stringRedisTemplate.opsForSet().members(indexKey);
            if (sids != null) {
                for (String sid : sids) {
                    stringRedisTemplate.opsForValue()
                            .set(DENYLIST_SID_PREFIX + sid, DENYLIST_VALUE, ttl, TimeUnit.SECONDS);
                    stringRedisTemplate.delete(SESSION_PREFIX + sid);
                }
            }
            stringRedisTemplate.delete(indexKey);

            log.info("KeycloakServiceImpl::revokeUser: revoked user_id={} and {} session(s)",
                    userId, sids == null ? 0 : sids.size());
        } catch (Exception e) {
            log.error("KeycloakServiceImpl::revokeUser: Redis write failed — user NOT revoked", e);
            throw new CustomException(Constants.AUTH_REVOCATION_FAILED,
                    Constants.AUTH_REVOCATION_FAILED_MSG, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Creates the Keycloak user, or updates them if they already exist. Never writes a credential:
     * passwords live in the catalogue and nowhere else.
     *
     * <p>Idempotent by design, returning {@code true} only when a user was created. The caller is a
     * catalogue whose publish is "push here, then persist ACTIVE", so every way our response can be
     * lost leaves it believing the push did not happen — a conflict on the retry would wedge the
     * record permanently. The update path rewrites {@code enabled} and all three attributes, so a
     * republish repairs drift instead of merely not failing.
     *
     * <p>This is also the re-enable path for INACTIVE -> ACTIVE.
     */
    @Override
    public boolean upsertUser(String userId, String orgId, String entityType, String email) {
        try {
            JsonNode existing = findUser(userId);
            if (existing != null) {
                updateUser(existing.path("id").asText(), userId, orgId, entityType, email);
                log.info("KeycloakServiceImpl::upsertUser: updated {}", userId);
                return false;
            }
            try {
                restTemplate.exchange(adminUsersUrl(), HttpMethod.POST,
                        adminEntity(userPayload(userId, orgId, entityType, email, true)), String.class);
            } catch (HttpClientErrorException.Conflict e) {
                // Either a concurrent publish of this same user, or the email belongs to somebody
                // else. Only the first is ours to fix; the second must reach the caller as a 409
                // because no amount of retrying will change it.
                JsonNode raced = findUser(userId);
                if (raced == null) {
                    log.warn("KeycloakServiceImpl::upsertUser: {} conflicts with another identity", userId);
                    throw new CustomException(Constants.AUTH_USER_CONFLICT,
                            Constants.AUTH_USER_CONFLICT_MSG, HttpStatus.CONFLICT);
                }
                updateUser(raced.path("id").asText(), userId, orgId, entityType, email);
                return false;
            }
            clearUserDenylist(userId);
            log.info("KeycloakServiceImpl::upsertUser: created {}", userId);
            return true;
        } catch (CustomException e) {
            throw e;
        } catch (HttpStatusCodeException e) {
            throw adminFailure("upsertUser", userId, e);
        } catch (RestClientException e) {
            log.error("KeycloakServiceImpl::upsertUser: Keycloak unreachable", e);
            throw unreachable();
        }
    }

    private void updateUser(String kcId, String userId, String orgId, String entityType, String email) {
        restTemplate.exchange(adminUsersUrl() + "/" + kcId, HttpMethod.PUT,
                adminEntity(userPayload(userId, orgId, entityType, email, false)), String.class);
        clearUserDenylist(userId);
    }

    /**
     * Sets {@code enabled=false} and ends every Keycloak session.
     *
     * <p>Best-effort, mirroring {@link #logoutFromKeycloak}: the Redis revocation is the half that
     * stops a blocked user who is already holding a valid access token, which is the part Keycloak
     * cannot do at all. A Keycloak blip must not fail the block.
     */
    @Override
    public boolean disableUser(String userId) {
        try {
            JsonNode existing = findUser(userId);
            if (existing == null) {
                log.warn("KeycloakServiceImpl::disableUser: no Keycloak user for {}", userId);
                return false;
            }
            String kcId = existing.path("id").asText();
            // Deliberately a partial representation: Keycloak only touches `attributes` when that
            // key is present, so this preserves user_id/org_id/entity_type without a
            // read-modify-write that could clobber them.
            restTemplate.exchange(adminUsersUrl() + "/" + kcId, HttpMethod.PUT,
                    adminEntity("{\"enabled\":false}"), String.class);
            restTemplate.exchange(adminUsersUrl() + "/" + kcId + "/logout", HttpMethod.POST,
                    adminEntity(null), String.class);
            log.info("KeycloakServiceImpl::disableUser: disabled {} and ended its sessions", userId);
            return true;
        } catch (Exception e) {
            log.warn("KeycloakServiceImpl::disableUser: could not disable {} in Keycloak; "
                    + "local revocation stands", userId);
            return false;
        }
    }

    /**
     * Deletes the Keycloak user. Returns {@code false} when there was nothing to delete.
     *
     * <p>Throws where {@link #disableUser} swallows: an undeleted user is the operation simply not
     * having happened, whereas a failed disable still leaves the Redis revocation in force.
     */
    @Override
    public boolean deleteUser(String userId) {
        try {
            JsonNode existing = findUser(userId);
            if (existing == null) {
                // Not an error. Delete is a converged end state, and a caller retrying a
                // half-finished cleanup must be able to succeed.
                log.info("KeycloakServiceImpl::deleteUser: nothing to delete for {}", userId);
                return false;
            }
            restTemplate.exchange(adminUsersUrl() + "/" + existing.path("id").asText(),
                    HttpMethod.DELETE, adminEntity(null), String.class);
            log.info("KeycloakServiceImpl::deleteUser: deleted {}", userId);
            return true;
        } catch (HttpClientErrorException.NotFound e) {
            return false;
        } catch (HttpStatusCodeException e) {
            throw adminFailure("deleteUser", userId, e);
        } catch (RestClientException e) {
            log.error("KeycloakServiceImpl::deleteUser: Keycloak unreachable", e);
            throw unreachable();
        }
    }

    /**
     * The Keycloak user matching a catalogue userId, or null. Username is the catalogue userId by
     * contract — {@code upsertUser} is what establishes that.
     */
    private JsonNode findUser(String userId) {
        String url = UriComponentsBuilder.fromUriString(adminUsersUrl())
                .queryParam("username", userId)
                .queryParam("exact", "true")
                .encode()
                .toUriString();
        ResponseEntity<JsonNode> response =
                restTemplate.exchange(url, HttpMethod.GET, adminEntity(null), JsonNode.class);
        JsonNode body = response.getBody();
        return body != null && body.isArray() && !body.isEmpty() ? body.get(0) : null;
    }

    /**
     * Built with Jackson rather than string concatenation: an email containing a quote would
     * otherwise emit broken JSON. Note the absence of a {@code credentials} array.
     */
    private String userPayload(String userId, String orgId, String entityType, String email, boolean create) {
        ObjectNode user = MAPPER.createObjectNode();
        if (create) {
            // Read-only once set; sending it on an update is at best a no-op and at worst a 400.
            user.put("username", userId);
        }
        user.put("enabled", true);
        if (StringUtils.isNotBlank(email)) {
            user.put("email", email);
            // Without this Keycloak raises a VERIFY_EMAIL required action, and the token request then
            // fails with "Account is not fully set up".
            user.put("emailVerified", true);
        }
        ObjectNode attributes = user.putObject("attributes");
        attributes.putArray(CLAIM_USER_ID).add(userId);
        attributes.putArray(CLAIM_ORG_ID).add(orgId);
        attributes.putArray(CLAIM_ENTITY_TYPE).add(entityType);
        return user.toString();
    }

    /**
     * A token for the client's own service account, cached until shortly before it expires.
     *
     * <p>Uses the client credentials the service already has, so no admin username or password is
     * configured anywhere. The account holds only {@code manage-users} and {@code view-users}.
     */
    @SuppressWarnings("unchecked")
    private String adminToken() {
        if (adminAccessToken != null && Instant.now().isBefore(adminAccessTokenExpiresAt)) {
            return adminAccessToken;
        }
        synchronized (adminTokenLock) {
            if (adminAccessToken != null && Instant.now().isBefore(adminAccessTokenExpiresAt)) {
                return adminAccessToken;
            }
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "client_credentials");
            form.add("client_id", vergProperties.getKeycloakClientId());
            form.add("client_secret", vergProperties.getKeycloakClientSecret());
            try {
                ResponseEntity<Map> response = restTemplate.exchange(
                        tokenEndpoint(), HttpMethod.POST, formEntity(form), Map.class);
                Map<String, Object> body = response.getBody();
                String token = body == null ? null : (String) body.get("access_token");
                if (StringUtils.isBlank(token)) {
                    log.error("KeycloakServiceImpl::adminToken: no access_token in the response");
                    throw idpFailed();
                }
                long expiresIn = body.get("expires_in") instanceof Number n ? n.longValue() : 0L;
                // Refresh early rather than on expiry: a token that dies mid-request would surface
                // to the catalogue as a failed publish. Flooring at 0 means a token shorter than the
                // skew is simply never cached.
                adminAccessTokenExpiresAt = Instant.now()
                        .plusSeconds(Math.max(expiresIn - ADMIN_TOKEN_SKEW_SECONDS, 0));
                adminAccessToken = token;
                return token;
            } catch (HttpStatusCodeException e) {
                // 401 here means a wrong secret, or serviceAccountsEnabled is still false.
                log.error("KeycloakServiceImpl::adminToken: client_credentials refused (status={})",
                        e.getStatusCode());
                throw idpFailed();
            } catch (RestClientException e) {
                log.error("KeycloakServiceImpl::adminToken: Keycloak unreachable", e);
                throw unreachable();
            }
        }
    }

    private HttpEntity<String> adminEntity(String json) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken());
        if (json != null) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }
        return new HttpEntity<>(json, headers);
    }

    /**
     * Re-enabling has to actually let the user log in again. {@code revokeUser} wrote a user-level
     * denylist entry that rejects <em>new</em> tokens too, so without this a republish would report
     * success while every login failed until the TTL expired.
     *
     * <p>Per-session entries are left in place on purpose: tokens issued before the block stay dead.
     */
    private void clearUserDenylist(String userId) {
        try {
            stringRedisTemplate.delete(DENYLIST_USER_PREFIX + userId);
        } catch (Exception e) {
            log.warn("KeycloakServiceImpl::clearUserDenylist: could not clear the denylist for {}", userId);
        }
    }

    private CustomException adminFailure(String operation, String userId, HttpStatusCodeException e) {
        if (e.getStatusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
            // Drop the cached token so one stale credential cannot wedge every later call.
            adminAccessTokenExpiresAt = Instant.EPOCH;
        }
        if (e.getStatusCode().value() == HttpStatus.CONFLICT.value()) {
            return new CustomException(Constants.AUTH_USER_CONFLICT,
                    Constants.AUTH_USER_CONFLICT_MSG, HttpStatus.CONFLICT);
        }
        // A 403 here almost always means manage-users/view-users was never granted.
        log.error("KeycloakServiceImpl::{}: admin API rejected the call for {} (status={})",
                operation, userId, e.getStatusCode());
        return idpFailed();
    }

    private CustomException idpFailed() {
        return new CustomException(Constants.AUTH_IDP_OPERATION_FAILED,
                Constants.AUTH_IDP_OPERATION_FAILED_MSG, HttpStatus.BAD_GATEWAY);
    }

    private CustomException unreachable() {
        return new CustomException(Constants.AUTH_UPSTREAM_UNAVAILABLE,
                Constants.AUTH_UPSTREAM_UNAVAILABLE_MSG, HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Override
    public boolean logoutFromKeycloak(String refreshToken) {
        if (StringUtils.isBlank(refreshToken)) {
            return false;
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", vergProperties.getKeycloakClientId());
        form.add("refresh_token", refreshToken);
        if (StringUtils.isNotBlank(vergProperties.getKeycloakClientSecret())) {
            form.add("client_secret", vergProperties.getKeycloakClientSecret());
        }
        try {
            restTemplate.exchange(logoutEndpoint(), HttpMethod.POST, formEntity(form), String.class);
            return true;
        } catch (RestClientException e) {
            // The Redis half already did the load-bearing work.
            log.warn("KeycloakServiceImpl::logoutFromKeycloak: failed; local revocation stands");
            return false;
        }
    }

    /**
     * True if this token, its session, or its user has been revoked.
     *
     * <p>When Redis cannot answer, falls back to Keycloak introspection, which knows about logouts
     * and disabled users. If neither can answer, fails closed.
     */
    private boolean isRevoked(DecodedJWT jwt) {
        try {
            if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(DENYLIST_JTI_PREFIX + jwt.getId()))) {
                return true;
            }
            String sid = jwt.getClaim(CLAIM_SID).asString();
            if (StringUtils.isNotBlank(sid)
                    && Boolean.TRUE.equals(stringRedisTemplate.hasKey(DENYLIST_SID_PREFIX + sid))) {
                return true;
            }
            String userId = resolveUserId(jwt);
            return StringUtils.isNotBlank(userId)
                    && Boolean.TRUE.equals(stringRedisTemplate.hasKey(DENYLIST_USER_PREFIX + userId));
        } catch (Exception e) {
            log.warn("KeycloakServiceImpl::isRevoked: Redis unavailable — falling back to introspection");
            return !isActiveAccordingToKeycloak(jwt.getToken());
        }
    }

    /**
     * Introspection requires this client to be in the token's audience, or Keycloak answers a bare
     * {@code {"active": false}} — see the audience mapper created by setup-realm.sh.
     */
    @SuppressWarnings("unchecked")
    private boolean isActiveAccordingToKeycloak(String token) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("client_id", vergProperties.getKeycloakClientId());
        if (StringUtils.isNotBlank(vergProperties.getKeycloakClientSecret())) {
            form.add("client_secret", vergProperties.getKeycloakClientSecret());
        }
        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    introspectEndpoint(), HttpMethod.POST, formEntity(form), Map.class);
            return response.getBody() != null && Boolean.TRUE.equals(response.getBody().get("active"));
        } catch (RestClientException e) {
            log.error("KeycloakServiceImpl::isActiveAccordingToKeycloak: introspection failed, Redis also down", e);
            throw new CustomException(Constants.AUTH_REVOCATION_FAILED,
                    Constants.AUTH_REVOCATION_FAILED_MSG, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    /** Prefer the catalogue id; fall back to the username so revocation works without the claim. */
    private String resolveUserId(DecodedJWT jwt) {
        return StringUtils.defaultIfBlank(
                jwt.getClaim(CLAIM_USER_ID).asString(), jwt.getClaim(CLAIM_PREFERRED_USERNAME).asString());
    }

    /** Reason is logged, never returned — telling a caller why their token failed helps an attacker. */
    private CustomException invalidToken(String reason) {
        log.warn("KeycloakServiceImpl::verifyToken: rejected — {}", reason);
        return new CustomException(Constants.AUTH_TOKEN_INVALID,
                Constants.AUTH_TOKEN_INVALID_MSG, HttpStatus.UNAUTHORIZED);
    }

    private HttpEntity<MultiValueMap<String, String>> formEntity(MultiValueMap<String, String> form) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return new HttpEntity<>(form, headers);
    }

    private String userSessionsKey(String userId) {
        return USER_SESSIONS_PREFIX + userId + USER_SESSIONS_SUFFIX;
    }

    private String realmUrl() {
        return vergProperties.getKeycloakBaseUrl() + "/realms/" + vergProperties.getKeycloakRealm();
    }

    private String tokenEndpoint() {
        return realmUrl() + "/protocol/openid-connect/token";
    }

    private String logoutEndpoint() {
        return realmUrl() + "/protocol/openid-connect/logout";
    }

    private String introspectEndpoint() {
        return realmUrl() + "/protocol/openid-connect/token/introspect";
    }

    private String adminUsersUrl() {
        return vergProperties.getKeycloakBaseUrl() + "/admin/realms/"
                + vergProperties.getKeycloakRealm() + "/users";
    }
}
