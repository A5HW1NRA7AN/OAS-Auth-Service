package com.catalogue.verg.auth.service.impl;

import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.keycloak.service.KeycloakService;
import com.catalogue.verg.core.util.Constants;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * Unit tests for the service layer, which is where the JSON contract the user-catalogue integrates
 * against actually lives. Keycloak is mocked; nothing here touches a network or a container.
 *
 * <p>The ordering assertions are the important ones. {@code auth_user_delete} revoking before
 * deleting is not a style preference: deleting a Keycloak user does not invalidate a JWT it already
 * signed, and once the user is gone there is nothing left to enumerate sessions for.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceImplTest {

    private static final String USER_ID = "user-000000000001";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private KeycloakService keycloakService;

    @InjectMocks
    private AuthServiceImpl service;

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
        verify(keycloakService, never()).upsertUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    @DisplayName("user create reports whether the user was created or updated")
    void userCreateReportsCreatedFlag() {
        String body = "{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\","
                + "\"entityType\":\"MAKER\",\"email\":\"a@b.example\"}";

        when(keycloakService.upsertUser(USER_ID, "org-1", "MAKER", "a@b.example")).thenReturn(true);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", true);

        when(keycloakService.upsertUser(USER_ID, "org-1", "MAKER", "a@b.example")).thenReturn(false);
        assertThat(service.authUserCreate(json(body)).getResult()).containsEntry("created", false);
    }

    @Test
    @DisplayName("email is optional — the catalogue may not have one")
    void userCreateAcceptsMissingEmail() {
        String body = "{\"userId\":\"" + USER_ID + "\",\"orgId\":\"org-1\",\"entityType\":\"MAKER\"}";

        service.authUserCreate(json(body));

        verify(keycloakService).upsertUser(USER_ID, "org-1", "MAKER", null);
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
}
