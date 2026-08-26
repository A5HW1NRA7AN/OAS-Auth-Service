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
    private static final String CLAIM_FUNCTIONAL_ROLE = "functional_role";
    private static final String CLAIM_ORG_NAME = "org_name";
    private static final String CLAIM_DISPLAY_NAME = "display_name";
    private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
    private static final String TOKEN_TYPE_BEARER = "Bearer";

    private static final String DENYLIST_JTI_PREFIX = "auth:denylist:jti:";
    private static final String DENYLIST_SID_PREFIX = "auth:denylist:sid:";
    private static final String DENYLIST_USER_PREFIX = "auth:denylist:user:";
    private static final String DENYLIST_VALUE = "1";

    // Session index, so "disable this user" can enumerate live sessions rather than wait for a TTL.
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

    /** Injected directly, not via a cache helper: a cache swallows errors, a denylist must not. */
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
        // No password field: the realm's direct grant flow has no password step, so Keycloak
        // resolves the user and enforces `enabled` only. setup-realm.sh step 4 is the other half.

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

    /** Keycloak returns invalid_grant for both unknown and disabled. No password here, so one
     * admin lookup on the failure path is safe and tells the caller which it was. */
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

        // RS256 pinned, never read from the header: the public key is published, so a header-trusting
        // verifier accepts a token signed with that key as an HS256 secret.
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

        // Refresh tokens pass every check above, so without this they would validate as 200.
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
            String session = MAPPER.createObjectNode()
                    .put(CLAIM_USER_ID, userId)
                    .put(CLAIM_ORG_ID, jwt.getClaim(CLAIM_ORG_ID).asString())
                    .put(CLAIM_FUNCTIONAL_ROLE, jwt.getClaim(CLAIM_FUNCTIONAL_ROLE).asString())
                    .put("username", jwt.getClaim(CLAIM_PREFERRED_USERNAME).asString())
                    .toString();

            stringRedisTemplate.opsForValue().set(SESSION_PREFIX + sid, session, ttl, TimeUnit.SECONDS);
            String indexKey = userSessionsKey(userId);
            stringRedisTemplate.opsForSet().add(indexKey, sid);
            stringRedisTemplate.expire(indexKey, ttl, TimeUnit.SECONDS);
        } catch (Exception e) {
            // A login must not fail over the index; the denylist still governs revocation.
            log.warn("KeycloakServiceImpl::recordSession: could not index session for {}", userId);
        }
    }

    /**
     * Denylists one token and its session. Both are needed: every refresh mints a new jti, so
     * revoking the jti alone leaves its siblings live. Values are a constant "1", never the token.
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
     * Revokes every live token for a user; disabling upstream only stops the next login.
     * Keyed on {@code user_id}, not {@code sub}, so callers pass the catalogue id they already hold.
     */
    @Override
    public void revokeUser(String userId) {
        try {
            long ttl = vergProperties.getKeycloakDenylistSidTtlSeconds();
            stringRedisTemplate.opsForValue()
                    .set(DENYLIST_USER_PREFIX + userId, DENYLIST_VALUE, ttl, TimeUnit.SECONDS);

            // Denylist each session by sid too, so nothing survives the user key expiring.
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
     * Creates or updates the Keycloak user, never a credential. Also the re-enable path.
     *
     * <p>Idempotent because the caller pushes here before persisting ACTIVE: a 409 on its retry
     * would wedge the record. The update rewrites enabled and all attributes, so it repairs drift.
     *
     * @return true only when a user was created
     */
    @Override
    public boolean upsertUser(CatalogueUser user) {
        String userId = user.userId();
        try {
            JsonNode existing = findUser(userId);
            if (existing != null) {
                updateUser(existing, user);
                log.info("KeycloakServiceImpl::upsertUser: updated {}", userId);
                return false;
            }
            try {
                restTemplate.exchange(adminUsersUrl(), HttpMethod.POST,
                        adminEntity(userPayload(user, true)), String.class);
            } catch (HttpClientErrorException.Conflict e) {
                // Either a concurrent publish of this user, or the email belongs to someone else.
                // Only the first is recoverable; the second must surface as a 409.
                JsonNode raced = findUser(userId);
                if (raced == null) {
                    log.warn("KeycloakServiceImpl::upsertUser: {} conflicts with another identity", userId);
                    throw new CustomException(Constants.AUTH_USER_CONFLICT,
                            Constants.AUTH_USER_CONFLICT_MSG, HttpStatus.CONFLICT);
                }
                updateUser(raced, user);
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

    /**
     * A Keycloak PUT that omits a field CLEARS it (verified), so "not mentioned" must mean "keep".
     *
     * <p>The merge is resolved into a record before the payload is built rather than inline in the
     * call: note that email/firstName/lastName are TOP-LEVEL Keycloak fields while orgName and
     * displayName are attributes, and reading either through the other's accessor compiles fine and
     * silently wipes the value on every republish.
     */
    private void updateUser(JsonNode existing, CatalogueUser user) {
        CatalogueUser merged = new CatalogueUser(
                user.userId(),
                user.orgId(),
                user.functionalRole(),
                StringUtils.defaultIfBlank(user.email(), existing.path("email").asText(null)),
                StringUtils.defaultIfBlank(user.firstName(), existing.path("firstName").asText(null)),
                StringUtils.defaultIfBlank(user.lastName(), existing.path("lastName").asText(null)),
                StringUtils.defaultIfBlank(user.orgName(), existingAttribute(existing, CLAIM_ORG_NAME)),
                StringUtils.defaultIfBlank(user.displayName(), existingAttribute(existing, CLAIM_DISPLAY_NAME)));

        restTemplate.exchange(adminUsersUrl() + "/" + existing.path("id").asText(), HttpMethod.PUT,
                adminEntity(userPayload(merged, false)), String.class);
        clearUserDenylist(user.userId());
    }

    /**
     * Reads a single-valued custom attribute back off the stored user. Keycloak represents every
     * attribute as an array, so the value is element 0; findUser already returned attributes, so
     * this costs no extra round trip.
     *
     * <p>The isTextual guard is load-bearing: MissingNode.asText() is "" and NullNode.asText() is
     * the literal "null", either of which would carry forward as though it were a real value.
     */
    private String existingAttribute(JsonNode existing, String name) {
        JsonNode first = existing.path("attributes").path(name).path(0);
        return first.isTextual() ? StringUtils.trimToNull(first.asText()) : null;
    }

    /**
     * Sets {@code enabled=false} and ends every Keycloak session.
     *
     * <p>A Keycloak failure returns false rather than throwing, since the Redis revocation already
     * stopped anyone holding a live token. An absent user throws 404 instead: nothing was revoked,
     * so a wrong identifier must not look like success. Takes the userId, not the email.
     */
    @Override
    public boolean disableUser(String userId) {
        try {
            JsonNode existing = findUser(userId);
            if (existing == null) {
                log.warn("KeycloakServiceImpl::disableUser: no Keycloak user for {} — nothing was "
                        + "revoked. This endpoint takes the userId, not the email.", userId);
                throw new CustomException(Constants.AUTH_USER_NOT_FOUND,
                        Constants.AUTH_USER_NOT_FOUND_MSG, HttpStatus.NOT_FOUND);
            }
            String kcId = existing.path("id").asText();
            // Partial payload: Keycloak only touches `attributes` when the key is present, so the
            // custom attributes survive without a read-modify-write.
            restTemplate.exchange(adminUsersUrl() + "/" + kcId, HttpMethod.PUT,
                    adminEntity("{\"enabled\":false}"), String.class);
            restTemplate.exchange(adminUsersUrl() + "/" + kcId + "/logout", HttpMethod.POST,
                    adminEntity(null), String.class);
            log.info("KeycloakServiceImpl::disableUser: disabled {} and ended its sessions", userId);
            return true;
        } catch (CustomException e) {
            throw e;
        } catch (Exception e) {
            log.warn("KeycloakServiceImpl::disableUser: could not disable {} in Keycloak; "
                    + "local revocation stands", userId);
            return false;
        }
    }

    /**
     * Deletes the Keycloak user; false when there was nothing to delete. Throws where
     * {@link #disableUser} swallows, because a failed delete leaves nothing else in force.
     */
    @Override
    public boolean deleteUser(String userId) {
        try {
            JsonNode existing = findUser(userId);
            if (existing == null) {
                // Not an error: a caller retrying a half-finished cleanup must be able to finish.
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

    /** The Keycloak user for a catalogue userId, or null. upsertUser sets username = userId. */
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

    /** Jackson, not concatenation: a quote in an email would emit broken JSON. No credentials. */
    private String userPayload(CatalogueUser catalogueUser, boolean create) {
        ObjectNode user = MAPPER.createObjectNode();
        if (create) {
            // Read-only once set; sending it on an update is at best a no-op and at worst a 400.
            user.put("username", catalogueUser.userId());
        }
        user.put("enabled", true);
        if (StringUtils.isNotBlank(catalogueUser.email())) {
            user.put("email", catalogueUser.email());
            // Without this Keycloak raises VERIFY_EMAIL and the grant fails "not fully set up".
            user.put("emailVerified", true);
        }
        // Stored as Keycloak's own fields, but projected by OUR first_name/last_name mappers: the
        // built-in profile scope's given_name/family_name mappers are deleted by setup-realm.sh.
        if (StringUtils.isNotBlank(catalogueUser.firstName())) {
            user.put("firstName", catalogueUser.firstName());
        }
        if (StringUtils.isNotBlank(catalogueUser.lastName())) {
            user.put("lastName", catalogueUser.lastName());
        }
        ObjectNode attributes = user.putObject("attributes");
        attributes.putArray(CLAIM_USER_ID).add(catalogueUser.userId());
        attributes.putArray(CLAIM_ORG_ID).add(catalogueUser.orgId());
        attributes.putArray(CLAIM_FUNCTIONAL_ROLE).add(catalogueUser.functionalRole());
        // Optional, and omitting the key is how Keycloak clears an attribute, so a blank needs no
        // branch of its own. An empty value would fail the User Profile's min-length validator
        // with a 400, which adminFailure has no branch for and would report as a bare 502.
        if (StringUtils.isNotBlank(catalogueUser.orgName())) {
            attributes.putArray(CLAIM_ORG_NAME).add(catalogueUser.orgName());
        }
        if (StringUtils.isNotBlank(catalogueUser.displayName())) {
            attributes.putArray(CLAIM_DISPLAY_NAME).add(catalogueUser.displayName());
        }
        return user.toString();
    }

    /**
     * A token for the client's own service account, cached until shortly before expiry. Uses the
     * client credentials already configured, so no admin password exists anywhere; the account
     * holds only {@code manage-users} and {@code view-users}.
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
                // Refresh early: a token dying mid-request looks like a failed publish to the
                // catalogue. Flooring at 0 means a token shorter than the skew is never cached.
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
     * Clears the user-level denylist entry {@code revokeUser} wrote, which also rejects new tokens —
     * without this a republish reports success while every login fails until the TTL expires.
     * Per-session entries stay: tokens issued before the block remain dead.
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
     * True if this token, its session or its user is revoked. Falls back to Keycloak introspection
     * when Redis cannot answer, and fails closed when neither can.
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

    /** Needs this client in the token's audience, or Keycloak answers a bare active:false. */
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
