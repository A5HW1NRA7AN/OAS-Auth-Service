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

    // ── auth_user_create ───────────────────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "{}",
            "{\"userId\":\"user-1\"}",
            "{\"userId\":\"user-1\",\"orgId\":\"org-1\"}",
            "{\"orgId\":\"org-1\",\"entityType\":\"MAKER\"}"
    })
    @DisplayName("user create requires userId, orgId and entityType")
    void userCreateRequiresIdentifiers(String body) {
        // orgId and entityType are required because a Keycloak user missing them mints tokens with a
        // null org_id, and every downstream tenant check then silently sees "no org".
        assertThatThrownBy(() -> service.authUserCreate(json(body)))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(keycloakService, never()).upsertUser(anyString(), anyString(), anyString(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("user create reports whether the user was created or updated")
    void userCreateReportsCreatedFlag() {
        String body = "{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"entityType\":\"MAKER\",\"email\":\"a@b.example\"}";

        when(keycloakService.upsertUser(USER_ID, "org-1", "MAKER", "a@b.example", null, null, null)).thenReturn(true);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", true);

        when(keycloakService.upsertUser(USER_ID, "org-1", "MAKER", "a@b.example", null, null, null)).thenReturn(false);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", false);
    }

    @Test
    @DisplayName("email is optional — the catalogue may not have one")
    void userCreateAcceptsMissingEmail() {
        String body = "{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\",\"entityType\":\"MAKER\"}";

        service.authUserCreate(json(body));

        verify(keycloakService).upsertUser(USER_ID, "org-1", "MAKER", null, null, null, null);
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

    // ── the optional profile fields and registries ────────────────────────────────────────────

    @Test
    @DisplayName("firstName, lastName and registries are passed through")
    void userCreatePassesOptionalFields() {
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"entityType\":\"MAKER\",\"firstName\":\"Asha\",\"lastName\":\"Rao\","
                + "\"registries\":[\"reg-a\",\"reg-b\"]}"));

        verify(keycloakService).upsertUser(USER_ID, "org-1", "MAKER", null,
                "Asha", "Rao", List.of("reg-a", "reg-b"));
    }

    @Test
    @DisplayName("registries are trimmed and de-duplicated in first-seen order")
    void userCreateSanitisesRegistries() {
        // Keycloak validates length 1..64 per value, so a blank would surface as a confusing 502.
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"entityType\":\"MAKER\",\"registries\":[\"reg-b\",\" \",\"reg-a\",\"reg-b\",\" reg-a \"]}"));

        verify(keycloakService).upsertUser(USER_ID, "org-1", "MAKER", null, null, null,
                List.of("reg-b", "reg-a"));
    }

    @Test
    @DisplayName("an empty registries array is passed through as empty, meaning clear")
    void userCreateEmptyRegistriesMeansClear() {
        // Distinct from absent, which is null and means "leave what is stored alone".
        service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"entityType\":\"MAKER\",\"registries\":[]}"));

        verify(keycloakService).upsertUser(USER_ID, "org-1", "MAKER", null, null, null, List.of());
    }

    @Test
    @DisplayName("a non-array registries value is a 400, not a silent single-element list")
    void userCreateRejectsNonArrayRegistries() {
        assertThatThrownBy(() -> service.authUserCreate(json("{\"userId\":\"" + USER_ID + "\","
                + "\"orgId\":\"org-1\",\"entityType\":\"MAKER\",\"registries\":\"reg-a\"}")))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_REQUEST);
        verify(keycloakService, never())
                .upsertUser(anyString(), anyString(), anyString(), any(), any(), any(), any());
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
    @DisplayName("a multi-valued registries claim comes back as a list")
    void validateReturnsRegistriesAsList() {
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"registries\":[\"reg-a\",\"reg-b\"]}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult()).containsEntry("registries", List.of("reg-a", "reg-b"));
    }

    @Test
    @DisplayName("an absent registries claim is null, never an empty list")
    void validateReturnsNullForAbsentRegistries() {
        // Keycloak omits an empty attribute, so [] would assert "holds none" on a silent token.
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"user_id\":\"" + USER_ID + "\"}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult()).containsEntry("registries", null);
    }

    @Test
    @DisplayName("the built-in profile claims are surfaced too")
    void validateReturnsProfileClaims() {
        when(keycloakService.verifyToken(anyString(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(tokenWith("{\"given_name\":\"Asha\",\"family_name\":\"Rao\","
                        + "\"email\":\"asha@example.org\"}"));

        CustomResponse response = service.authTokenValidate(json("{\"token\":\"x\"}"));

        assertThat(response.getResult())
                .containsEntry("given_name", "Asha")
                .containsEntry("family_name", "Rao")
                .containsEntry("email", "asha@example.org");
    }
}
