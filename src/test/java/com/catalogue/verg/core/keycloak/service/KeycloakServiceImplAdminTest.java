package com.catalogue.verg.core.keycloak.service;

import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The Keycloak admin plane: creating, disabling and deleting users, and the service-account token
 * behind them. The token endpoint and admin API share one mocked RestTemplate, so stubs are
 * separated by URL and response type — Map for tokens, JsonNode for lookups, String for writes.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KeycloakServiceImplAdminTest {

    private static final String USER_ID = "user-000000000001";
    private static final String ORG_ID = "org-000000000001";
    private static final String FUNCTIONAL_ROLE = "MAKER";
    private static final String KC_ID = "kc-internal-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private KeycloakServiceImpl service;

    @Mock
    private StringRedisTemplate stringRedisTemplate;

    @Mock
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        VergProperties props = new VergProperties();
        props.setKeycloakBaseUrl("http://localhost:8180");
        props.setKeycloakRealm("OAS");
        props.setKeycloakClientId("oas-auth-service");
        props.setKeycloakClientSecret("test-secret");
        props.setKeycloakDenylistSidTtlSeconds(900L);

        service = new KeycloakServiceImpl();
        ReflectionTestUtils.setField(service, "vergProperties", props);
        ReflectionTestUtils.setField(service, "restTemplate", restTemplate);
        ReflectionTestUtils.setField(service, "stringRedisTemplate", stringRedisTemplate);

        stubAdminToken(300);
    }

    /** The client_credentials call that yields the service-account token. */
    private void stubAdminToken(long expiresIn) {
        lenient().when(restTemplate.exchange(contains("/protocol/openid-connect/token"),
                        eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("access_token", "admin-token", "expires_in", expiresIn)));
    }

    /** What GET /users?username=… answers. Pass "[]" for "no such user". */
    private void stubUserLookup(String json) {
        try {
            lenient().when(restTemplate.exchange(contains("/users?username="),
                            eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                    .thenReturn(ResponseEntity.ok(MAPPER.readTree(json)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String existingUser(boolean enabled) {
        return "[{\"id\":\"" + KC_ID + "\",\"username\":\"" + USER_ID + "\",\"enabled\":" + enabled + "}]";
    }

    /** An existing user already holding the two optional attributes, for the carry-forward tests. */
    private String existingUserWithAttributes(String orgName, String displayName) {
        return "[{\"id\":\"" + KC_ID + "\",\"username\":\"" + USER_ID + "\",\"enabled\":true,"
                + "\"attributes\":{\"org_name\":[\"" + orgName + "\"],"
                + "\"display_name\":[\"" + displayName + "\"]}}]";
    }

    /** The identifiers-only publish: every optional field null, so it exercises carry-forward. */
    private KeycloakService.CatalogueUser basicUser() {
        return userWith(null, null, null, null, null);
    }

    private KeycloakService.CatalogueUser userWithEmail(String email) {
        return userWith(email, null, null, null, null);
    }

    private KeycloakService.CatalogueUser userWith(String email, String firstName, String lastName,
                                                   String orgName, String displayName) {
        return new KeycloakService.CatalogueUser(USER_ID, ORG_ID, FUNCTIONAL_ROLE, email,
                firstName, lastName, orgName, displayName);
    }

    private JsonNode capturedBody(HttpMethod method, String urlFragment) throws Exception {
        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(contains(urlFragment), eq(method), captor.capture(), eq(String.class));
        return MAPPER.readTree((String) captor.getValue().getBody());
    }

    // ── service-account token ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("the admin token is fetched once and reused across calls")
    void adminTokenIsFetchedOnceAndReused() {
        stubUserLookup(existingUser(true));

        service.upsertUser(basicUser());
        service.upsertUser(basicUser());

        verify(restTemplate, times(1))
                .exchange(contains("/protocol/openid-connect/token"), eq(HttpMethod.POST), any(), eq(Map.class));
    }

    @Test
    @DisplayName("a token expiring inside the refresh skew is never cached")
    void shortLivedAdminTokenIsRefetched() {
        // expires_in below the 30s skew floors the cached lifetime at zero, so every request has to
        // go back to Keycloak. Asserted arithmetically rather than by sleeping.
        stubAdminToken(5);
        stubUserLookup(existingUser(true));

        service.upsertUser(basicUser());
        service.upsertUser(basicUser());

        // Four, not two: each upsert authorises two admin requests (the lookup and the write), and
        // with nothing cacheable each one fetches its own token. Contrast
        // adminTokenIsFetchedOnceAndReused, where the same four requests share a single token.
        verify(restTemplate, times(4))
                .exchange(contains("/protocol/openid-connect/token"), eq(HttpMethod.POST), any(), eq(Map.class));
    }

    @Test
    @DisplayName("a 401 from the admin API drops the cached token instead of wedging every later call")
    void adminTokenIsClearedAfterUnauthorized() {
        stubUserLookup(existingUser(true));
        when(restTemplate.exchange(contains("/users/" + KC_ID), eq(HttpMethod.PUT), any(), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "unauthorized",
                        null, null, null));

        assertThatThrownBy(() -> service.upsertUser(basicUser()))
                .isInstanceOf(CustomException.class);

        assertThat(ReflectionTestUtils.getField(service, "adminAccessTokenExpiresAt"))
                .isEqualTo(java.time.Instant.EPOCH);
    }

    @Test
    @DisplayName("client_credentials refused -> 502, not a confusing 500")
    void clientCredentialsRefusedIsBadGateway() {
        // The realistic cause is serviceAccountsEnabled still being false, or a stale .env secret.
        when(restTemplate.exchange(contains("/protocol/openid-connect/token"),
                eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "invalid_client",
                        null, null, null));

        assertThatThrownBy(() -> service.deleteUser(USER_ID))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_IDP_OPERATION_FAILED)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.BAD_GATEWAY);
    }

    // ── upsert ─────────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("upsert creates the user with the required attributes and no credential")
    void upsertCreatesWhenAbsent() throws Exception {
        stubUserLookup("[]");

        assertThat(service.upsertUser(userWithEmail("a@b.example"))).isTrue();

        JsonNode body = capturedBody(HttpMethod.POST, "/users");
        assertThat(body.path("username").asText()).isEqualTo(USER_ID);
        assertThat(body.path("enabled").asBoolean()).isTrue();
        assertThat(body.path("emailVerified").asBoolean()).isTrue();
        assertThat(body.path("attributes").path("user_id").get(0).asText()).isEqualTo(USER_ID);
        assertThat(body.path("attributes").path("org_id").get(0).asText()).isEqualTo(ORG_ID);
        assertThat(body.path("attributes").path("functional_role").get(0).asText()).isEqualTo(FUNCTIONAL_ROLE);
        // The whole point of this architecture: Keycloak stores no password.
        assertThat(body.has("credentials")).isFalse();
    }

    @Test
    @DisplayName("upsert on an existing user updates it, re-enables it, and omits the read-only username")
    void upsertUpdatesAndReEnables() throws Exception {
        stubUserLookup(existingUser(false));

        assertThat(service.upsertUser(basicUser())).isFalse();

        JsonNode body = capturedBody(HttpMethod.PUT, "/users/" + KC_ID);
        assertThat(body.path("enabled").asBoolean()).isTrue();
        assertThat(body.has("username")).isFalse();
        assertThat(body.path("attributes").path("org_id").get(0).asText()).isEqualTo(ORG_ID);
    }

    @Test
    @DisplayName("upsert clears the user denylist so a re-enabled user can log in immediately")
    void upsertClearsUserDenylist() {
        // Without this a republish reports success while every login fails until the TTL expires.
        stubUserLookup(existingUser(false));

        service.upsertUser(basicUser());

        verify(stringRedisTemplate).delete("auth:denylist:user:" + USER_ID);
    }

    @Test
    @DisplayName("a 409 for somebody else's email is reported as a conflict, not retried")
    void upsertConflictOnAnotherIdentityIsConflict() {
        stubUserLookup("[]");
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.CONFLICT, "conflict",
                        null, null, null));

        assertThatThrownBy(() -> service.upsertUser(userWithEmail("taken@b.example")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_USER_CONFLICT)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("a 409 caused by a concurrent publish of the same user converges to an update")
    void upsertConflictBecomesUpdateWhenUserNowExists() {
        // First lookup finds nothing, the create races another publish, the re-read finds it.
        try {
            when(restTemplate.exchange(contains("/users?username="),
                            eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                    .thenReturn(ResponseEntity.ok(MAPPER.readTree("[]")))
                    .thenReturn(ResponseEntity.ok(MAPPER.readTree(existingUser(true))));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.CONFLICT, "conflict",
                        null, null, null));

        assertThat(service.upsertUser(basicUser())).isFalse();
        verify(restTemplate).exchange(contains("/users/" + KC_ID), eq(HttpMethod.PUT), any(), eq(String.class));
    }

    @Test
    @DisplayName("Keycloak unreachable during upsert -> 503, so the caller retries")
    void upsertUnreachableIsServiceUnavailable() {
        stubUserLookup("[]");
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThatThrownBy(() -> service.upsertUser(basicUser()))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("a 403 during upsert -> 502: manage-users was probably never granted")
    void upsertForbiddenIsBadGateway() {
        stubUserLookup("[]");
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN, "forbidden",
                        null, null, null));

        assertThatThrownBy(() -> service.upsertUser(basicUser()))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_IDP_OPERATION_FAILED);
    }

    // ── disable ────────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("disable sends exactly {enabled:false} so the custom attributes survive")
    void disableSendsPartialRepresentation() throws Exception {
        stubUserLookup(existingUser(true));

        assertThat(service.disableUser(USER_ID)).isTrue();

        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(contains("/users/" + KC_ID), eq(HttpMethod.PUT),
                captor.capture(), eq(String.class));
        JsonNode body = MAPPER.readTree((String) captor.getValue().getBody());
        // Keycloak only touches `attributes` when the key is present, so omitting it preserves
        // user_id/org_id/functional_role without a read-modify-write.
        assertThat(body.fieldNames()).toIterable().containsExactly("enabled");
        assertThat(body.path("enabled").asBoolean()).isFalse();
        verify(restTemplate).exchange(contains("/logout"), eq(HttpMethod.POST), any(), eq(String.class));
    }

    @Test
    @DisplayName("disable is best-effort: a Keycloak failure returns false rather than throwing")
    void disableSwallowsFailures() {
        // The Redis revocation is what actually stopped the blocked user, so a blip here must not
        // fail the block.
        stubUserLookup(existingUser(true));
        when(restTemplate.exchange(contains("/users/" + KC_ID), eq(HttpMethod.PUT), any(), eq(String.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThat(service.disableUser(USER_ID)).isFalse();
    }

    @Test
    @DisplayName("disable on an unknown user is a loud 404, not a quiet false")
    void disableUnknownUserIsNotFound() {
        // Nothing was revoked, so success would hide a caller passing the wrong identifier — most
        // likely the email, since that is what auth_token_create takes.
        stubUserLookup("[]");

        assertThatThrownBy(() -> service.disableUser(USER_ID))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_USER_NOT_FOUND)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.NOT_FOUND);
        verify(restTemplate, never()).exchange(contains("/logout"), any(), any(), eq(String.class));
    }

    // ── delete ─────────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("delete removes the user and reports it")
    void deleteRemovesUser() {
        stubUserLookup(existingUser(true));

        assertThat(service.deleteUser(USER_ID)).isTrue();
        verify(restTemplate).exchange(contains("/users/" + KC_ID), eq(HttpMethod.DELETE), any(), eq(String.class));
    }

    @Test
    @DisplayName("delete on an already-absent user succeeds without issuing a DELETE")
    void deleteIsIdempotent() {
        // Delete is a converged end state. A 404 here would make the retry of a half-finished
        // cleanup fail forever.
        stubUserLookup("[]");

        assertThat(service.deleteUser(USER_ID)).isFalse();
        verify(restTemplate, never()).exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(String.class));
    }

    // ── token issuance ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("requestToken sends no password field at all")
    void requestTokenSendsNoPassword() {
        when(restTemplate.exchange(contains("/protocol/openid-connect/token"),
                eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("access_token", "at", "refresh_token", "rt")));

        service.requestToken(USER_ID);

        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(contains("/protocol/openid-connect/token"),
                eq(HttpMethod.POST), captor.capture(), eq(Map.class));
        @SuppressWarnings("unchecked")
        Map<String, Object> form = (Map<String, Object>) captor.getValue().getBody();
        assertThat(form).containsKeys("grant_type", "client_id", "username", "client_secret");
        assertThat(form).doesNotContainKey("password");
        assertThat(form.get("username").toString()).contains(USER_ID);
    }

    /**
     * Keycloak refuses the password grant but still honours client_credentials. Both hit the same
     * URL, so the stub discriminates on {@code grant_type}; matching on URL alone broke the admin
     * lookup in the failure path and collapsed every diagnosis into a 503.
     */
    @SuppressWarnings("unchecked")
    private void stubPasswordGrantRefused() {
        lenient().when(restTemplate.exchange(contains("/protocol/openid-connect/token"),
                        eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenAnswer(invocation -> {
                    HttpEntity<org.springframework.util.MultiValueMap<String, String>> entity =
                            invocation.getArgument(2);
                    String grantType = entity.getBody() == null
                            ? null : entity.getBody().getFirst("grant_type");
                    if ("client_credentials".equals(grantType)) {
                        return ResponseEntity.ok(Map.of("access_token", "admin-token", "expires_in", 300L));
                    }
                    throw HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "invalid_grant",
                            null, null, null);
                });
    }

    @Test
    @DisplayName("a refused grant for an unprovisioned user -> 404, telling the caller to publish")
    void requestTokenUnknownUserIsNotFound() {
        stubPasswordGrantRefused();
        stubUserLookup("[]");

        assertThatThrownBy(() -> service.requestToken(USER_ID))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_USER_NOT_FOUND)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("a refused grant for a disabled user -> 403, distinct from not provisioned")
    void requestTokenDisabledUserIsForbidden() {
        stubPasswordGrantRefused();
        stubUserLookup(existingUser(false));

        assertThatThrownBy(() -> service.requestToken(USER_ID))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_USER_DISABLED)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("a refused grant we cannot explain -> 502, because it means the flow is misconfigured")
    void requestTokenRefusedForEnabledUserIsBadGateway() {
        // The user exists and is enabled, so the direct grant flow should have issued a token. That
        // is a configuration fault, not a caller error.
        stubPasswordGrantRefused();
        stubUserLookup(existingUser(true));

        assertThatThrownBy(() -> service.requestToken(USER_ID))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_IDP_OPERATION_FAILED)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.BAD_GATEWAY);
    }

    // ── the profile fields and the two optional attributes ─────────────────────────────────────

    @Test
    @DisplayName("every field lands in its own place — six consecutive Strings transpose silently")
    void upsertCreatesWithEveryFieldDistinct() throws Exception {
        // All eight values distinct and recognisable. The record names the components, but its
        // constructor is still positional, so this is what actually catches a swapped pair.
        stubUserLookup("[]");

        service.upsertUser(new KeycloakService.CatalogueUser(
                "u-1", "o-1", "MAKER", "e@x.example", "FIRST", "LAST", "ORGNAME", "DISPLAYNAME"));

        JsonNode body = capturedBody(HttpMethod.POST, "/users");
        assertThat(body.path("username").asText()).isEqualTo("u-1");
        assertThat(body.path("email").asText()).isEqualTo("e@x.example");
        assertThat(body.path("firstName").asText()).isEqualTo("FIRST");
        assertThat(body.path("lastName").asText()).isEqualTo("LAST");

        JsonNode attributes = body.path("attributes");
        assertThat(attributes.path("user_id").get(0).asText()).isEqualTo("u-1");
        assertThat(attributes.path("org_id").get(0).asText()).isEqualTo("o-1");
        assertThat(attributes.path("functional_role").get(0).asText()).isEqualTo("MAKER");
        assertThat(attributes.path("org_name").get(0).asText()).isEqualTo("ORGNAME");
        assertThat(attributes.path("display_name").get(0).asText()).isEqualTo("DISPLAYNAME");
        // The rename is only total when the retired names appear nowhere.
        assertThat(attributes.has("entity_type")).isFalse();
        assertThat(attributes.has("registries")).isFalse();
        assertThat(body.has("credentials")).isFalse();
    }

    @Test
    @DisplayName("absent optional attributes are omitted entirely, so no claim is emitted for them")
    void upsertOmitsAbsentOptionalAttributes() throws Exception {
        // Absent means no claim. Writing "" instead would fail the User Profile's min-length
        // validator with a 400, which adminFailure has no branch for and reports as a bare 502.
        stubUserLookup("[]");

        service.upsertUser(userWithEmail("a@b.example"));

        JsonNode attributes = capturedBody(HttpMethod.POST, "/users").path("attributes");
        assertThat(attributes.has("org_name")).isFalse();
        assertThat(attributes.has("display_name")).isFalse();
        assertThat(attributes.path("functional_role").get(0).asText()).isEqualTo(FUNCTIONAL_ROLE);
    }

    @Test
    @DisplayName("an update that omits orgName and displayName carries the stored values forward")
    void updateOmittingOptionalAttributesCarriesThemForward() throws Exception {
        // A Keycloak PUT that omits a key DELETES it, so "not mentioned" must mean "keep" — without
        // this merge every identifiers-only republish would silently wipe both.
        stubUserLookup(existingUserWithAttributes("Bharat Agri", "FIELD_OFFICER"));

        service.upsertUser(basicUser());

        JsonNode attributes = capturedBody(HttpMethod.PUT, "/users/" + KC_ID).path("attributes");
        assertThat(attributes.path("org_name").get(0).asText()).isEqualTo("Bharat Agri");
        assertThat(attributes.path("display_name").get(0).asText()).isEqualTo("FIELD_OFFICER");
    }

    @Test
    @DisplayName("an update with new values replaces the stored ones")
    void updateWithNewOptionalAttributesReplaces() throws Exception {
        stubUserLookup(existingUserWithAttributes("Bharat Agri", "FIELD_OFFICER"));

        service.upsertUser(userWith(null, null, null, "Nova Agri", "DISTRICT_ADMIN"));

        JsonNode attributes = capturedBody(HttpMethod.PUT, "/users/" + KC_ID).path("attributes");
        assertThat(attributes.path("org_name").get(0).asText()).isEqualTo("Nova Agri");
        assertThat(attributes.path("display_name").get(0).asText()).isEqualTo("DISTRICT_ADMIN");
        // The required three must survive the update.
        assertThat(attributes.path("user_id").get(0).asText()).isEqualTo(USER_ID);
        assertThat(attributes.path("org_id").get(0).asText()).isEqualTo(ORG_ID);
        assertThat(attributes.path("functional_role").get(0).asText()).isEqualTo(FUNCTIONAL_ROLE);
    }

    @Test
    @DisplayName("a stored entity_type is not carried forward — the rename is not a merge")
    void updateDropsTheRetiredAttributes() throws Exception {
        // A user provisioned before the rename still holds entity_type and registries. Nothing reads
        // either any more, and re-emitting them would keep the stale claims alive if a mapper for
        // them were ever restored.
        stubUserLookup("[{\"id\":\"" + KC_ID + "\",\"username\":\"" + USER_ID + "\",\"enabled\":true,"
                + "\"attributes\":{\"entity_type\":[\"CHECKER\"],\"registries\":[\"reg-a\"]}}]");

        service.upsertUser(basicUser());

        JsonNode attributes = capturedBody(HttpMethod.PUT, "/users/" + KC_ID).path("attributes");
        assertThat(attributes.has("entity_type")).isFalse();
        assertThat(attributes.has("registries")).isFalse();
        assertThat(attributes.path("functional_role").get(0).asText()).isEqualTo(FUNCTIONAL_ROLE);
    }

    @Test
    @DisplayName("an update that omits firstName and lastName carries those forward too")
    void updateOmittingNamesCarriesThemForward() throws Exception {
        // Verified: omitting a top-level field in a PUT nulls it, so these need carrying forward too.
        stubUserLookup("[{\"id\":\"" + KC_ID + "\",\"username\":\"" + USER_ID + "\",\"enabled\":true,"
                + "\"firstName\":\"Asha\",\"lastName\":\"Rao\",\"email\":\"a@b.example\"}]");

        service.upsertUser(basicUser());

        JsonNode body = capturedBody(HttpMethod.PUT, "/users/" + KC_ID);
        assertThat(body.path("firstName").asText()).isEqualTo("Asha");
        assertThat(body.path("lastName").asText()).isEqualTo("Rao");
        assertThat(body.path("email").asText()).isEqualTo("a@b.example");
    }
}
