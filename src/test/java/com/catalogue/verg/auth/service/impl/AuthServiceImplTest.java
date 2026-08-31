package com.catalogue.verg.auth.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.catalogue.verg.core.catalogue.service.CatalogueService;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.keycloak.service.KeycloakService;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The service layer, where the JSON contract the catalogue integrates against lives. Keycloak is
 * mocked. The ordering assertions matter most: delete must revoke first, because a deleted user's
 * already-signed JWTs stay valid and there are then no sessions left to enumerate.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceImplTest {

    private static final String USER_ID = "user-000000000001";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private KeycloakService keycloakService;

    @Mock
    private CatalogueService catalogueService;

    @InjectMocks
    private AuthServiceImpl service;

    /** A plain @Value holder, so it is populated here rather than by standing up a context. */
    private final VergProperties props = new VergProperties();

    @BeforeEach
    void setUp() {
        // Set explicitly, not inherited: these tests cover the trusting path. The shipped default is true.
        props.setCatalogueValidateEnabled(false);
        props.setCatalogueBaseUrl("http://localhost:8082");
        props.setCatalogueVerifyPath("/user/v1/verify");
        ReflectionTestUtils.setField(service, "vergProperties", props);
    }

    private JsonNode json(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ── auth_token_create ──────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("token create passes the userId through and returns Keycloak's response verbatim")
    void tokenCreatePassesUserId() {
        when(keycloakService.requestToken(USER_ID))
                .thenReturn(new java.util.HashMap<>(java.util.Map.of("access_token", "at")));

        CustomResponse response = service.authTokenCreate(json("{\"userId\":\"" + USER_ID + "\"}"));

        verify(keycloakService).requestToken(USER_ID);
        assertThat(response.getResult()).containsEntry("access_token", "at");
        assertThat(response.getResponseCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("token create without a userId is a 400, not a 401")
    void tokenCreateRequiresUserId() {
        // A missing field is a malformed request. Only a rejected identity is an auth failure.
        assertThatThrownBy(() -> service.authTokenCreate(json("{}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.BAD_REQUEST);
        verify(keycloakService, never()).requestToken(anyString());
    }

    // ── auth_token_refresh ─────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("refresh returns Keycloak's new token pair verbatim and re-indexes the session")
    void tokenRefreshReturnsNewPairAndReIndexes() {
        // A real signed token, so the best-effort decode inside indexSession actually succeeds.
        String access = tokenWith("{\"sid\":\"session-1\",\"user_id\":\"" + USER_ID + "\"}").getToken();
        when(keycloakService.refreshToken("rt-old")).thenReturn(
                new java.util.HashMap<>(java.util.Map.of("access_token", access, "refresh_token", "rt-new")));

        CustomResponse response = service.authTokenRefresh(json("{\"refreshToken\":\"rt-old\"}"));

        verify(keycloakService).refreshToken("rt-old");
        verify(keycloakService).recordSession(any());
        assertThat(response.getResult())
                .containsEntry("access_token", access)
                .containsEntry("refresh_token", "rt-new");
        assertThat(response.getResponseCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("refresh without a refreshToken is a 400, and Keycloak is never called")
    void tokenRefreshRequiresTheToken() {
        assertThatThrownBy(() -> service.authTokenRefresh(json("{}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.BAD_REQUEST);
        verify(keycloakService, never()).refreshToken(anyString());
    }

    @Test
    @DisplayName("a refusal from Keycloak propagates, and nothing is indexed")
    void tokenRefreshPropagatesRefusal() {
        // Keycloak collapses expired, malformed and session-ended refresh tokens into one 401.
        when(keycloakService.refreshToken("rt-dead")).thenThrow(new CustomException(
                Constants.AUTH_TOKEN_INVALID, Constants.AUTH_TOKEN_INVALID_MSG, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.authTokenRefresh(json("{\"refreshToken\":\"rt-dead\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_TOKEN_INVALID)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.UNAUTHORIZED);
        verify(keycloakService, never()).recordSession(any());
    }

    // ── auth_user_create ───────────────────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "{}",
            "{\"userId\":\"user-1\"}",
            "{\"userId\":\"user-1\",\"orgId\":\"org-1\"}",
            "{\"orgId\":\"org-1\",\"functionalRole\":\"MAKER\",\"email\":\"a@b.example\"}",
            // The email is the login identifier the catalogue checks a password against, so a user
            // published without one could never authenticate.
            "{\"userId\":\"user-1\",\"orgId\":\"org-1\",\"functionalRole\":\"MAKER\"}",
            // The hard rename: entityType is the OLD name and buys no compatibility. If this body
            // ever succeeds, someone has quietly re-added a fallback.
            "{\"userId\":\"user-1\",\"orgId\":\"org-1\",\"entityType\":\"MAKER\",\"email\":\"a@b.example\"}"
    })
    @DisplayName("user create requires userId, orgId, functionalRole and email — and rejects the old entityType")
    void userCreateRequiresIdentifiers(String body) {
        // orgId and functionalRole are required because a Keycloak user missing them mints tokens
        // with a null org_id, and every downstream tenant check then silently sees "no org".
        assertThatThrownBy(() -> service.authUserCreate(json(body)))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(keycloakService, never()).upsertUser(any());
    }

    @Test
    @DisplayName("user create reports whether the user was created or updated")
    void userCreateReportsCreatedFlag() {
        String body = "{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"functionalRole\":\"MAKER\",\"email\":\"a@b.example\"}";
        var expected = new KeycloakService.CatalogueUser(
                USER_ID, "org-1", "MAKER", "a@b.example", null, null, null, null);

        when(keycloakService.upsertUser(expected)).thenReturn(true);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", true);

        when(keycloakService.upsertUser(expected)).thenReturn(false);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", false);
    }

    // ── auth_user_revoke ───────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("revoke kills tokens first, then disables in Keycloak")
    void revokeRevokesThenDisables() {
        when(keycloakService.disableUser(USER_ID)).thenReturn(true);

        CustomResponse response = service.authUserRevoke(json("{\"userId\":\"" + USER_ID + "\"}"));

        InOrder order = inOrder(keycloakService);
        order.verify(keycloakService).revokeUser(USER_ID);
        order.verify(keycloakService).disableUser(USER_ID);
        assertThat(response.getResult()).containsEntry("revoked", true)
                .containsEntry("keycloakDisabled", "ok");
    }

    @Test
    @DisplayName("a failed Keycloak disable still returns 200, reported in the body")
    void revokeReportsFailedDisable() {
        // Best-effort by design: the Redis revocation already stopped the blocked user, so a Keycloak
        // blip must not fail the block.
        when(keycloakService.disableUser(USER_ID)).thenReturn(false);

        CustomResponse response = service.authUserRevoke(json("{\"userId\":\"" + USER_ID + "\"}"));

        assertThat(response.getResponseCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getResult()).containsEntry("keycloakDisabled", "failed");
    }

    @Test
    @DisplayName("a failed revocation stops the disable — the block is not silently half-applied")
    void revokeDoesNotDisableWhenRevocationFails() {
        doThrow(new CustomException(Constants.AUTH_REVOCATION_FAILED, "boom",
                HttpStatus.SERVICE_UNAVAILABLE)).when(keycloakService).revokeUser(USER_ID);

        assertThatThrownBy(() -> service.authUserRevoke(json("{\"userId\":\"" + USER_ID + "\"}")))
                .isInstanceOf(CustomException.class);

        verify(keycloakService, never()).disableUser(anyString());
    }

    // ── auth_user_delete ───────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("delete revokes before deleting")
    void deleteRevokesBeforeDeleting() {
        when(keycloakService.deleteUser(USER_ID)).thenReturn(true);

        CustomResponse response = service.authUserDelete(json("{\"userId\":\"" + USER_ID + "\"}"));

        InOrder order = inOrder(keycloakService);
        order.verify(keycloakService).revokeUser(USER_ID);
        order.verify(keycloakService).deleteUser(USER_ID);
        assertThat(response.getResult()).containsEntry("revoked", true).containsEntry("deleted", true);
    }

    @Test
    @DisplayName("a failed revocation stops the delete, so no live tokens are orphaned")
    void deleteDoesNotDeleteWhenRevocationFails() {
        // If the delete ran first and the Redis purge then failed, the user would be gone from
        // Keycloak while their issued tokens stayed valid and unfindable.
        doThrow(new CustomException(Constants.AUTH_REVOCATION_FAILED, "boom",
                HttpStatus.SERVICE_UNAVAILABLE)).when(keycloakService).revokeUser(USER_ID);

        assertThatThrownBy(() -> service.authUserDelete(json("{\"userId\":\"" + USER_ID + "\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_REVOCATION_FAILED);

        verify(keycloakService, never()).deleteUser(anyString());
    }

    @Test
    @DisplayName("deleting an already-absent user is a 200 with deleted:false, not a 404")
    void deleteIsIdempotent() {
        // Delete is a converged end state. A caller retrying a half-finished cleanup must be able to
        // complete it, and the Redis purge above still needs to run.
        when(keycloakService.deleteUser(USER_ID)).thenReturn(false);

        CustomResponse response = service.authUserDelete(json("{\"userId\":\"" + USER_ID + "\"}"));

        assertThat(response.getResponseCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getResult()).containsEntry("deleted", false).containsEntry("revoked", true);
        verify(keycloakService).revokeUser(USER_ID);
    }

    @Test
    @DisplayName("delete without a userId is a 400 and touches nothing")
    void deleteRequiresUserId() {
        assertThatThrownBy(() -> service.authUserDelete(json("{}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(keycloakService, never()).revokeUser(anyString());
        verify(keycloakService, never()).deleteUser(anyString());
    }

    // ── the flag, and the two bypasses it must not allow ──────────────────────────────────────

    @Test
    @DisplayName("with verification off, credentials are refused — no accidental half-verified mode")
    void tokenCreateWithCredentialsIsRejectedWhenVerificationIsOff() {
        assertThatThrownBy(() -> service.authTokenCreate(
                json("{\"email\":\"asha@example.org\",\"password\":\"pw\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(catalogueService, never()).verifyCredentials(anyString(), anyString());
        verify(keycloakService, never()).requestToken(anyString());
    }

    @Test
    @DisplayName("with verification on, the token is issued for the userId the CATALOGUE returned")
    void tokenCreateUsesTheCatalogueUserId() {
        props.setCatalogueValidateEnabled(true);
        when(catalogueService.verifyCredentials("asha@example.org", "pw")).thenReturn("user-from-catalogue");

        service.authTokenCreate(json("{\"email\":\"asha@example.org\",\"password\":\"pw\"}"));

        verify(catalogueService).verifyCredentials("asha@example.org", "pw");
        verify(keycloakService).requestToken("user-from-catalogue");
    }

    @Test
    @DisplayName("a userId in the body is IGNORED in verified mode")
    void tokenCreateIgnoresABodyUserIdInVerifiedMode() {
        // Honouring it would let one valid password mint a token for any other account.
        props.setCatalogueValidateEnabled(true);
        when(catalogueService.verifyCredentials("asha@example.org", "pw")).thenReturn("user-asha");

        service.authTokenCreate(json(
                "{\"email\":\"asha@example.org\",\"password\":\"pw\",\"userId\":\"user-victim\"}"));

        verify(keycloakService).requestToken("user-asha");
        verify(keycloakService, never()).requestToken("user-victim");
    }

    @Test
    @DisplayName("with verification on, a bare userId cannot downgrade out of verification")
    void tokenCreateWithOnlyAUserIdIsRejectedWhenVerificationIsOn() {
        // If the path were chosen by body shape, this request would skip the password check entirely.
        props.setCatalogueValidateEnabled(true);

        assertThatThrownBy(() -> service.authTokenCreate(json("{\"userId\":\"" + USER_ID + "\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(keycloakService, never()).requestToken(anyString());
    }

    @Test
    @DisplayName("with verification on, a missing password is a 400 and the catalogue is not called")
    void tokenCreateRequiresPasswordInVerifiedMode() {
        props.setCatalogueValidateEnabled(true);

        assertThatThrownBy(() -> service.authTokenCreate(json("{\"email\":\"asha@example.org\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(catalogueService, never()).verifyCredentials(anyString(), anyString());
        verify(keycloakService, never()).requestToken(anyString());
    }

    @Test
    @DisplayName("a rejected password propagates as 401 and issues nothing")
    void tokenCreatePropagatesRejection() {
        props.setCatalogueValidateEnabled(true);
        when(catalogueService.verifyCredentials(anyString(), anyString()))
                .thenThrow(new CustomException(Constants.AUTH_INVALID_CREDENTIALS,
                        Constants.AUTH_INVALID_CREDENTIALS_MSG, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.authTokenCreate(
                json("{\"email\":\"asha@example.org\",\"password\":\"wrong\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.UNAUTHORIZED);
        verify(keycloakService, never()).requestToken(anyString());
    }

    @Test
    @DisplayName("a catalogue outage propagates as 503 and issues nothing — fail closed")
    void tokenCreatePropagatesCatalogueOutage() {
        props.setCatalogueValidateEnabled(true);
        when(catalogueService.verifyCredentials(anyString(), anyString()))
                .thenThrow(new CustomException(Constants.AUTH_UPSTREAM_UNAVAILABLE,
                        Constants.AUTH_UPSTREAM_UNAVAILABLE_MSG, HttpStatus.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> service.authTokenCreate(
                json("{\"email\":\"asha@example.org\",\"password\":\"pw\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
        verify(keycloakService, never()).requestToken(anyString());
    }

    // ── the optional profile fields ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("every field lands in its own component — eight positional values transpose silently")
    void userCreatePassesOptionalFields() {
        // Deliberately all-distinct and all-recognisable: with six consecutive Strings on the
        // record, a swapped pair compiles and only a value-by-value assertion can see it.
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"functionalRole\":\"MAKER\",\"email\":\"asha@example.org\","
                + "\"firstName\":\"Asha\",\"lastName\":\"Rao\","
                + "\"orgName\":\"Bharat Agri\",\"displayName\":\"FIELD_OFFICER\"}"));

        verify(keycloakService).upsertUser(new KeycloakService.CatalogueUser(
                USER_ID, "org-1", "MAKER", "asha@example.org",
                "Asha", "Rao", "Bharat Agri", "FIELD_OFFICER"));
    }

    @Test
    @DisplayName("absent optional fields are null, so the stored value carries forward")
    void userCreateOmitsAbsentOptionalFields() {
        // Null, never "" — a blank would fail Keycloak's min-length validator with a 400 that
        // adminFailure has no branch for and would report as a bare 502.
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"functionalRole\":\"MAKER\",\"email\":\"asha@example.org\"}"));

        verify(keycloakService).upsertUser(new KeycloakService.CatalogueUser(
                USER_ID, "org-1", "MAKER", "asha@example.org", null, null, null, null));
    }

    @Test
    @DisplayName("an explicit null displayName is treated as absent, not as a clear")
    void userCreateTreatsExplicitNullAsAbsent() {
        // displayName is nullable upstream, so a serialiser may well emit it. Retries are the norm
        // on this endpoint, and a stray null must not erase a name the catalogue itself set.
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"functionalRole\":\"MAKER\",\"email\":\"asha@example.org\",\"displayName\":null}"));

        verify(keycloakService).upsertUser(new KeycloakService.CatalogueUser(
                USER_ID, "org-1", "MAKER", "asha@example.org", null, null, null, null));
    }

    // ── auth_token_validate reads the new claims ──────────────────────────────────────────────

    /** Signed with HMAC because these tests never verify — verifyToken is mocked. */
    private DecodedJWT tokenWith(String claimsJson) {
        try {
            var builder = JWT.create().withSubject("sub-1");
            JsonNode claims = MAPPER.readTree(claimsJson);
            claims.fields().forEachRemaining(entry -> {
                JsonNode value = entry.getValue();
                if (value.isArray()) {
                    List<String> list = new java.util.ArrayList<>();
                    value.forEach(v -> list.add(v.asText()));
                    builder.withClaim(entry.getKey(), list);
                } else {
                    builder.withClaim(entry.getKey(), value.asText());
                }
            });
            return JWT.decode(builder.sign(Algorithm.HMAC256("test-only")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("every OAS claim is surfaced, under its new name")
    void validateReturnsTheOasClaims() {
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"user_id\":\"" + USER_ID + "\",\"org_id\":\"org-1\","
                        + "\"org_name\":\"Bharat Agri\",\"functional_role\":\"MAKER\","
                        + "\"display_name\":\"FIELD_OFFICER\"}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult())
                .containsEntry("user_id", USER_ID)
                .containsEntry("org_id", "org-1")
                .containsEntry("org_name", "Bharat Agri")
                .containsEntry("functional_role", "MAKER")
                .containsEntry("display_name", "FIELD_OFFICER");
        // The rename is only total when the retired keys appear nowhere in the response.
        assertThat(response.getResult()).doesNotContainKeys("entity_type", "registries");
    }

    @Test
    @DisplayName("an absent optional claim is null, never omitted from the response")
    void validateReturnsNullForAbsentClaims() {
        // A key that is present-and-null says "the token does not carry this". A key that is simply
        // missing is indistinguishable from a field this service forgot to surface.
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"user_id\":\"" + USER_ID + "\"}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult())
                .containsEntry("org_name", null)
                .containsEntry("display_name", null)
                .containsEntry("functional_role", null);
    }

    @Test
    @DisplayName("the name claims are first_name/last_name, not Keycloak's given_name/family_name")
    void validateReturnsProfileClaims() {
        // setup-realm.sh deletes the built-in profile scope's two name mappers, so a token carrying
        // given_name/family_name means that deletion did not take.
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"first_name\":\"Asha\",\"last_name\":\"Rao\","
                        + "\"email\":\"asha@example.org\"}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult())
                .containsEntry("first_name", "Asha")
                .containsEntry("last_name", "Rao")
                .containsEntry("email", "asha@example.org")
                .doesNotContainKeys("given_name", "family_name");
    }
}
