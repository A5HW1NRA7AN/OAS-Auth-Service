package com.catalogue.verg.core.keycloak.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/** Token verification, where a mistake is an auth bypass; keys and tokens are made in-process. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KeycloakServiceImplTest {

    private static final String ISSUER = "http://localhost:8180/realms/OAS";
    private static final String CLIENT_ID = "oas-auth-service";
    private static final String KID = "test-key-id";
    private static final long DEVICE_TTL = 2_592_000L;

    private KeycloakServiceImpl service;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @Mock
    private JwkProvider jwkProvider;

    @Mock
    private Jwk jwk;

    @Mock
    private StringRedisTemplate stringRedisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    /** revokeToken/revokeUser now maintain the per-user session index. */
    @Mock
    private org.springframework.data.redis.core.SetOperations<String, String> setOperations;

    /** The per-user index of PIN-login devices, which revokeUser also clears. */
    @Mock
    private org.springframework.data.redis.core.HashOperations<String, Object, Object> hashOperations;

    /** Field-injected in production, so collaborators are set by reflection. */
    @Mock
    private org.springframework.web.client.RestTemplate restTemplate;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        publicKey = (RSAPublicKey) pair.getPublic();
        privateKey = (RSAPrivateKey) pair.getPrivate();

        // VergProperties is a plain @Value holder, so no Spring context is needed.
        VergProperties props = new VergProperties();
        props.setKeycloakIssuer(ISSUER);
        props.setKeycloakBaseUrl("http://localhost:8180");
        props.setKeycloakRealm("OAS");
        props.setKeycloakClientId(CLIENT_ID);
        props.setKeycloakClientSecret("test-secret");
        props.setKeycloakClockSkewSeconds(30L);
        props.setKeycloakDenylistSidTtlSeconds(900L);
        props.setPinDeviceTtlSeconds(DEVICE_TTL);

        service = new KeycloakServiceImpl();
        ReflectionTestUtils.setField(service, "vergProperties", props);
        ReflectionTestUtils.setField(service, "jwkProvider", jwkProvider);
        ReflectionTestUtils.setField(service, "stringRedisTemplate", stringRedisTemplate);
        ReflectionTestUtils.setField(service, "restTemplate", restTemplate);

        lenient().when(jwkProvider.get(anyString())).thenReturn(jwk);
        lenient().when(jwk.getPublicKey()).thenReturn(publicKey);
        lenient().when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        lenient().when(stringRedisTemplate.opsForSet()).thenReturn(setOperations);
        lenient().when(stringRedisTemplate.opsForHash()).thenReturn(hashOperations);
        lenient().when(stringRedisTemplate.hasKey(anyString())).thenReturn(false);
    }

    /** A token that should pass every check. Individual tests override one piece at a time. */
    private JWTCreator.Builder validToken() {
        return JWT.create()
                .withKeyId(KID)
                .withIssuer(ISSUER)
                .withSubject("f4638019-146a-4a47-8eb5-2b6f931ba914")
                .withJWTId("jti-" + System.nanoTime())
                .withClaim("typ", "Bearer")
                .withClaim("azp", CLIENT_ID)
                .withClaim("sid", "session-123")
                .withClaim("preferred_username", "user-000000000001")
                // Real tokens carry the client in aud; without it introspection (the Redis fallback) rejects all.
                .withAudience(CLIENT_ID)
                // Real tokens carry these from the oas-profile client scope.
                .withClaim("user_id", "user-000000000001")
                .withClaim("org_id", "org-000000000001")
                .withClaim("functional_role", "MAKER")
                .withClaim("org_name", "Bharat Agri")
                .withClaim("display_name", "FIELD_OFFICER")
                .withClaim("first_name", "Asha")
                .withClaim("last_name", "Rao")
                .withIssuedAt(new Date(System.currentTimeMillis() - 1000))
                .withExpiresAt(new Date(System.currentTimeMillis() + 300_000));
    }

    private String sign(JWTCreator.Builder builder, RSAPrivateKey key) {
        return builder.sign(Algorithm.RSA256(null, key));
    }

    // --- the happy path ---

    @Test
    @DisplayName("a well-formed access token is accepted")
    void acceptsValidToken() {
        String token = sign(validToken(), privateKey);

        DecodedJWT decoded = service.verifyToken(token, false);

        assertThat(decoded.getClaim("preferred_username").asString()).isEqualTo("user-000000000001");
        assertThat(decoded.getIssuer()).isEqualTo(ISSUER);
    }

    // --- THE auth-bypass test ---

    @Test
    @DisplayName("a token signed with the PUBLIC KEY as an HMAC secret is rejected")
    void rejectsAlgorithmConfusionAttack() {
        // Algorithm confusion: the public key used as an HS256 secret must fail while RS256 is pinned.
        String publicKeyAsSecret = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String forged = JWT.create()
                .withKeyId(KID)
                .withIssuer(ISSUER)
                .withSubject("attacker")
                .withJWTId("forged-jti")
                .withClaim("typ", "Bearer")
                .withClaim("azp", CLIENT_ID)
                .withClaim("preferred_username", "admin")
                .withExpiresAt(new Date(System.currentTimeMillis() + 300_000))
                .sign(Algorithm.HMAC256(publicKeyAsSecret));

        assertThatThrownBy(() -> service.verifyToken(forged, false))
                .isInstanceOf(CustomException.class)
                .satisfies(e -> {
                    CustomException ce = (CustomException) e;
                    assertThat(ce.getCode()).isEqualTo(Constants.AUTH_TOKEN_INVALID);
                    assertThat(ce.getHttpStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                });
    }

    // --- the individual checks ---

    @Test
    @DisplayName("a token signed by a different key is rejected")
    void rejectsWrongSigningKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPrivateKey otherKey = (RSAPrivateKey) generator.generateKeyPair().getPrivate();

        String token = sign(validToken(), otherKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("a tampered signature is rejected")
    void rejectsTamperedToken() {
        String token = sign(validToken(), privateKey);
        String[] parts = token.split("\\.");
        String signature = parts[2];

        // First char, not last: the last base64url char of RSA-2048 carries 2 bits, so flipping it flakes.
        char original = signature.charAt(0);
        String tampered = parts[0] + "." + parts[1] + "."
                + (original == 'A' ? 'B' : 'A') + signature.substring(1);

        assertThatThrownBy(() -> service.verifyToken(tampered, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("a token from another realm is rejected")
    void rejectsWrongIssuer() {
        String token = sign(validToken().withIssuer("http://evil.example/realms/OAS"), privateKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("a token issued to a different client is rejected")
    void rejectsWrongAzp() {
        String token = sign(validToken().withClaim("azp", "some-other-client"), privateKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("a REFRESH token is rejected even though it is validly signed")
    void rejectsRefreshToken() {
        // Same key, issuer and azp as an access token: only the typ check stops a refresh token.
        String token = sign(validToken().withClaim("typ", "Refresh"), privateKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("an expired token is rejected with its own error code")
    void rejectsExpiredToken() {
        String token = sign(validToken()
                .withExpiresAt(new Date(System.currentTimeMillis() - 600_000)), privateKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_EXPIRED);
    }

    @Test
    @DisplayName("an expired token IS accepted when ignoreExpiry is set, so it can be revoked")
    void acceptsExpiredTokenWhenIgnoringExpiry() {
        // Invalidate must accept an expired token: its session may still have live siblings.
        String token = sign(validToken()
                .withExpiresAt(new Date(System.currentTimeMillis() - 600_000)), privateKey);

        DecodedJWT decoded = service.verifyToken(token, true);

        assertThat(decoded.getClaim("sid").asString()).isEqualTo("session-123");
    }

    @Test
    @DisplayName("a token with no jti is rejected, because it could never be revoked")
    void rejectsMissingJti() {
        String token = sign(JWT.create()
                .withKeyId(KID)
                .withIssuer(ISSUER)
                .withClaim("typ", "Bearer")
                .withClaim("azp", CLIENT_ID)
                .withExpiresAt(new Date(System.currentTimeMillis() + 300_000)), privateKey);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
    }

    // --- the denylist ---

    @Test
    @DisplayName("a token whose jti is on the denylist is rejected")
    void rejectsRevokedByJti() {
        String token = sign(validToken(), privateKey);
        String jti = JWT.decode(token).getId();
        when(stringRedisTemplate.hasKey("auth:denylist:jti:" + jti)).thenReturn(true);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
    }

    @Test
    @DisplayName("a token whose SESSION was revoked is rejected, even with a fresh jti")
    void rejectsRevokedBySid() {
        // Why the sid entry exists: each refresh mints a new jti, so one jti leaves the session alive.
        String token = sign(validToken(), privateKey);
        when(stringRedisTemplate.hasKey("auth:denylist:sid:session-123")).thenReturn(true);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
    }

    @Test
    @DisplayName("a token whose USER was revoked is rejected, even with a fresh jti and session")
    void rejectsRevokedByUser() {
        // Blocking must kill tokens already issued; disabling upstream only stops the next login.
        String token = sign(validToken(), privateKey);
        when(stringRedisTemplate.hasKey("auth:denylist:user:user-000000000001")).thenReturn(true);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
    }

    @Test
    @DisplayName("user revocation still works when the token has no user_id claim")
    void rejectsRevokedByUserFallsBackToUsername() {
        // user_id needs the oas-profile scope; preferred_username keeps revocation working without it.
        String token = sign(JWT.create()
                .withKeyId(KID).withIssuer(ISSUER).withJWTId("jti-nofallback")
                .withClaim("typ", "Bearer").withClaim("azp", CLIENT_ID)
                .withClaim("preferred_username", "user-000000000009")
                .withExpiresAt(new Date(System.currentTimeMillis() + 300_000)), privateKey);
        when(stringRedisTemplate.hasKey("auth:denylist:user:user-000000000009")).thenReturn(true);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
    }

    @Test
    @DisplayName("revokeUser writes a user-scoped denylist entry")
    void revokeUserWritesDenylistEntry() {
        service.revokeUser("user-000000000001");

        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:denylist:user:user-000000000001"),
                org.mockito.ArgumentMatchers.eq("1"),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    @DisplayName("when Redis is down, falls back to Keycloak introspection and accepts an active token")
    void fallsBackToIntrospectionWhenRedisUnavailable() {
        // A Redis outage degrades to one introspection call instead of failing auth.
        String token = sign(validToken(), privateKey);
        when(stringRedisTemplate.hasKey(anyString()))
                .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));
        stubIntrospection(true);

        DecodedJWT decoded = service.verifyToken(token, false);

        assertThat(decoded.getClaim("preferred_username").asString()).isEqualTo("user-000000000001");
    }

    @Test
    @DisplayName("Redis down and Keycloak says inactive -> rejected")
    void rejectsWhenIntrospectionSaysInactive() {
        // Covers a logged-out session and a disabled user; both verified live to report active=false.
        String token = sign(validToken(), privateKey);
        when(stringRedisTemplate.hasKey(anyString()))
                .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));
        stubIntrospection(false);

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
    }

    @Test
    @DisplayName("Redis down AND Keycloak unreachable -> fails closed with 503")
    void failsClosedWhenBothStoresAreDown() {
        // With neither store able to answer "was this revoked?", the only safe answer is no.
        String token = sign(validToken(), privateKey);
        when(stringRedisTemplate.hasKey(anyString()))
                .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));
        when(restTemplate.exchange(anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.<Class<Map>>any()))
                .thenThrow(new org.springframework.web.client.ResourceAccessException("keycloak down"));

        assertThatThrownBy(() -> service.verifyToken(token, false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_REVOCATION_FAILED)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
    }

    /** Makes the introspection endpoint answer with the given `active` verdict. */
    private void stubIntrospection(boolean active) {
        when(restTemplate.exchange(anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.<Class<Map>>any()))
                .thenReturn(org.springframework.http.ResponseEntity.ok(Map.of("active", active)));
    }

    @Test
    @DisplayName("login records a session and indexes it under the user")
    void recordSessionIndexesUnderUser() {
        DecodedJWT jwt = JWT.decode(sign(validToken(), privateKey));

        service.recordSession(jwt);

        // Key pinned too: nothing reads these back, so a claim rename that missed it would fail silently.
        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:session:session-123"),
                org.mockito.ArgumentMatchers.contains("\"functional_role\":\"MAKER\""),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(setOperations)
                .add("auth:user:user-000000000001:sessions", "session-123");
    }

    @Test
    @DisplayName("a failed session write does not fail the login")
    void recordSessionIsBestEffort() {
        // The denylist still governs, so an index write failure must not fail a good login.
        when(stringRedisTemplate.opsForValue())
                .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));

        service.recordSession(JWT.decode(sign(validToken(), privateKey)));   // must not throw
    }

    @Test
    @DisplayName("revoking a user denylists every one of its sessions and clears the index")
    void revokeUserClearsEverySession() {
        // Without the index, revocation would rely on one user-level entry expiring.
        when(setOperations.members("auth:user:user-000000000001:sessions"))
                .thenReturn(new java.util.LinkedHashSet<>(java.util.List.of("sid-a", "sid-b")));

        service.revokeUser("user-000000000001");

        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:denylist:sid:sid-a"),
                org.mockito.ArgumentMatchers.eq("1"),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:denylist:sid:sid-b"),
                org.mockito.ArgumentMatchers.eq("1"),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(stringRedisTemplate).delete("auth:session:sid-a");
        org.mockito.Mockito.verify(stringRedisTemplate).delete("auth:session:sid-b");
        org.mockito.Mockito.verify(stringRedisTemplate).delete("auth:user:user-000000000001:sessions");
    }

    @Test
    @DisplayName("a blank token is a 400, not a 401")
    void rejectsBlankToken() {
        assertThatThrownBy(() -> service.verifyToken("   ", false))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("revoking writes both a jti entry and a sid entry")
    void revokeWritesBothDenylistEntries() {
        String token = sign(validToken(), privateKey);
        DecodedJWT jwt = JWT.decode(token);

        service.revokeToken(jwt);

        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:denylist:jti:" + jwt.getId()),
                org.mockito.ArgumentMatchers.eq("1"),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(valueOperations).set(
                org.mockito.ArgumentMatchers.eq("auth:denylist:sid:session-123"),
                org.mockito.ArgumentMatchers.eq("1"),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    @DisplayName("a failed Redis write surfaces as 503, never a silent success")
    void revokeFailsLoudlyWhenRedisDown() {
        String token = sign(validToken(), privateKey);
        DecodedJWT jwt = JWT.decode(token);
        org.mockito.Mockito.doThrow(new org.springframework.dao.QueryTimeoutException("redis down"))
                .when(valueOperations)
                .set(anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong(),
                        org.mockito.ArgumentMatchers.any());

        assertThatThrownBy(() -> service.revokeToken(jwt))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_REVOCATION_FAILED);
    }

    // ── PIN-login devices ──────────────────────────────────────────────────────────────────────

    private static final String PIN_USER = "user-000000000001";
    private static final String HANDLE = "test-device-handle-0000000000000000000000000";

    private static String sha256(String value) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    /** Makes HANDLE resolve to a stored device for PIN_USER. */
    private void stubDevice() throws Exception {
        when(valueOperations.get("auth:device:" + sha256(HANDLE)))
                .thenReturn("{\"user_id\":\"" + PIN_USER + "\",\"device_id\":\"device-1\"}");
    }

    @Test
    @DisplayName("enrolling stores the handle's digest, never the handle, for the full device life")
    void enrolDeviceStoresOnlyTheDigest() throws Exception {
        KeycloakService.DeviceEnrolment enrolment = service.enrolDevice(PIN_USER, "Asha's Pixel");

        // 32 random bytes, Base64-URL without padding.
        assertThat(enrolment.deviceHandle()).hasSize(43).matches("[A-Za-z0-9_-]+");
        String digest = sha256(enrolment.deviceHandle());
        org.mockito.ArgumentCaptor<String> value = org.mockito.ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(valueOperations).set(org.mockito.ArgumentMatchers.eq("auth:device:" + digest),
                value.capture(), org.mockito.ArgumentMatchers.eq(DEVICE_TTL),
                org.mockito.ArgumentMatchers.eq(java.util.concurrent.TimeUnit.SECONDS));
        assertThat(value.getValue())
                .contains("\"user_id\":\"" + PIN_USER + "\"")
                .contains("\"device_id\":\"" + enrolment.deviceId() + "\"")
                .doesNotContain(enrolment.deviceHandle());
        org.mockito.Mockito.verify(hashOperations)
                .put("auth:user:" + PIN_USER + ":devices", enrolment.deviceId(), digest);
    }

    @Test
    @DisplayName("an unknown device is a 401 and spends no attempt")
    void claimOnUnknownDeviceSpendsNothing() {
        assertThatThrownBy(() -> service.claimPinAttempt(HANDLE))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID);
        org.mockito.Mockito.verify(valueOperations, org.mockito.Mockito.never()).increment(anyString());
    }

    @Test
    @DisplayName("a claim spends the attempt BEFORE the PIN is checked and returns the device's user")
    void claimSpendsTheAttemptFirst() throws Exception {
        stubDevice();
        when(valueOperations.increment("auth:pin:fail:" + sha256(HANDLE))).thenReturn(1L);

        assertThat(service.claimPinAttempt(HANDLE)).isEqualTo(PIN_USER);

        org.mockito.Mockito.verify(stringRedisTemplate).expire("auth:pin:fail:" + sha256(HANDLE),
                DEVICE_TTL, java.util.concurrent.TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("a claim past the fifth attempt is refused without a PIN check, and the device goes")
    void claimPastTheLimitRemovesTheDevice() throws Exception {
        // Only reachable by requests racing the one that spent the last attempt.
        stubDevice();
        when(valueOperations.increment("auth:pin:fail:" + sha256(HANDLE))).thenReturn(6L);

        assertThatThrownBy(() -> service.claimPinAttempt(HANDLE))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_REVOKED);
        org.mockito.Mockito.verify(stringRedisTemplate).delete(java.util.List.of(
                "auth:device:" + sha256(HANDLE), "auth:pin:fail:" + sha256(HANDLE)));
        org.mockito.Mockito.verify(hashOperations).delete("auth:user:" + PIN_USER + ":devices", "device-1");
    }

    @Test
    @DisplayName("Redis down during a claim is a 503 — a PIN that cannot be counted is never checked")
    void claimFailsClosedWhenRedisIsDown() {
        when(valueOperations.get(anyString()))
                .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));

        assertThatThrownBy(() -> service.claimPinAttempt(HANDLE))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("the fifth wrong PIN removes the device")
    void fifthWrongPinRemovesTheDevice() throws Exception {
        stubDevice();
        when(valueOperations.get("auth:pin:fail:" + sha256(HANDLE))).thenReturn("5");

        assertThat(service.settlePinAttempt(HANDLE, KeycloakService.PinAttempt.WRONG)).isTrue();

        org.mockito.Mockito.verify(stringRedisTemplate).delete(java.util.List.of(
                "auth:device:" + sha256(HANDLE), "auth:pin:fail:" + sha256(HANDLE)));
    }

    @Test
    @DisplayName("a wrong PIN below the limit keeps the device and leaves the attempt spent")
    void wrongPinBelowTheLimitKeepsTheDevice() throws Exception {
        when(valueOperations.get("auth:pin:fail:" + sha256(HANDLE))).thenReturn("4");

        assertThat(service.settlePinAttempt(HANDLE, KeycloakService.PinAttempt.WRONG)).isFalse();

        org.mockito.Mockito.verify(stringRedisTemplate, org.mockito.Mockito.never())
                .delete(org.mockito.ArgumentMatchers.<java.util.Collection<String>>any());
        org.mockito.Mockito.verify(valueOperations, org.mockito.Mockito.never()).decrement(anyString());
    }

    @Test
    @DisplayName("an unchecked PIN gives the attempt back; a correct one resets the counter")
    void uncheckedRefundsAndCorrectResets() throws Exception {
        String failKey = "auth:pin:fail:" + sha256(HANDLE);

        service.settlePinAttempt(HANDLE, KeycloakService.PinAttempt.UNCHECKED);
        org.mockito.Mockito.verify(valueOperations).decrement(failKey);

        service.settlePinAttempt(HANDLE, KeycloakService.PinAttempt.CORRECT);
        org.mockito.Mockito.verify(stringRedisTemplate).delete(failKey);
    }

    @Test
    @DisplayName("revoking a user deletes every PIN device — deleted, not denylisted, so a republish cannot revive one")
    void revokeUserDeletesEveryDevice() {
        when(hashOperations.values("auth:user:" + PIN_USER + ":devices"))
                .thenReturn(java.util.List.of("digest-a", "digest-b"));

        service.revokeUser(PIN_USER);

        org.mockito.Mockito.verify(stringRedisTemplate)
                .delete(java.util.List.of("auth:device:digest-a", "auth:pin:fail:digest-a"));
        org.mockito.Mockito.verify(stringRedisTemplate)
                .delete(java.util.List.of("auth:device:digest-b", "auth:pin:fail:digest-b"));
        org.mockito.Mockito.verify(stringRedisTemplate).delete("auth:user:" + PIN_USER + ":devices");
    }
}
