package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

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
    public Map<String, Object> requestToken(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", vergProperties.getKeycloakClientId());
        form.add("username", username);
        form.add("password", password);
        if (StringUtils.isNotBlank(vergProperties.getKeycloakClientSecret())) {
            form.add("client_secret", vergProperties.getKeycloakClientSecret());
        }

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    tokenEndpoint(), HttpMethod.POST, formEntity(form), Map.class);
            return response.getBody();
        } catch (HttpClientErrorException e) {
            // Keycloak distinguishes "Invalid user credentials" from "Account disabled". We collapse
            // both, plus unknown users, into one message — the difference only helps an attacker.
            log.warn("KeycloakServiceImpl::requestToken: rejected by Keycloak (status={})", e.getStatusCode());
            throw new CustomException(Constants.AUTH_INVALID_CREDENTIALS,
                    Constants.AUTH_INVALID_CREDENTIALS_MSG, HttpStatus.UNAUTHORIZED);
        } catch (RestClientException e) {
            // Never surface the cause: it leaks the internal hostname and port.
            log.error("KeycloakServiceImpl::requestToken: Keycloak unreachable", e);
            throw new CustomException(Constants.AUTH_UPSTREAM_UNAVAILABLE,
                    Constants.AUTH_UPSTREAM_UNAVAILABLE_MSG, HttpStatus.SERVICE_UNAVAILABLE);
        }
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
}
