package com.catalogue.verg.core.catalogue.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The credential check against the catalogue contract: which failures must NOT become a 401. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CatalogueServiceImplTest {

    private static final String BASE_URL = "http://localhost:8082";
    private static final String VERIFY_PATH = "/user/v1/verify";
    private static final String VERIFY_PIN_PATH = "/user/v1/verify_pin";
    private static final String EMAIL = "asha@example.org";
    private static final String PASSWORD = "Sup3r-S3cret!";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CatalogueServiceImpl service = new CatalogueServiceImpl();

    @Mock
    private RestTemplate restTemplate;

    CatalogueServiceImplTest() {
        VergProperties props = new VergProperties();
        props.setCatalogueBaseUrl(BASE_URL);
        props.setCatalogueVerifyPath(VERIFY_PATH);
        props.setCatalogueVerifyPinPath(VERIFY_PIN_PATH);
        ReflectionTestUtils.setField(service, "vergProperties", props);
    }

    @org.junit.jupiter.api.BeforeEach
    void injectRestTemplate() {
        ReflectionTestUtils.setField(service, "restTemplate", restTemplate);
    }

    private void stubResponse(String json) {
        try {
            when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                    .thenReturn(ResponseEntity.ok(json == null ? null : MAPPER.readTree(json)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ── success ────────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("posts email and password to base-url + verify-path")
    void postsCredentialsToConfiguredUrl() {
        stubResponse("{\"result\":{\"userId\":\"user-1\",\"status\":\"ACTIVE\"}}");

        service.verifyCredentials(EMAIL, PASSWORD);

        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(eq(BASE_URL + VERIFY_PATH), eq(HttpMethod.POST),
                captor.capture(), eq(JsonNode.class));
        @SuppressWarnings("unchecked")
        Map<String, String> body = (Map<String, String>) captor.getValue().getBody();
        // Password untrimmed: it is bytes, not a name.
        assertThat(body).containsEntry("email", EMAIL).containsEntry("password", PASSWORD);
    }

    @Test
    @DisplayName("2xx with result.userId returns that userId")
    void successReturnsUserId() {
        stubResponse("{\"result\":{\"userId\":\"user-1\",\"email\":\"a@b.example\","
                + "\"status\":\"ACTIVE\"},\"message\":\"successfully verified\"}");

        assertThat(service.verifyCredentials(EMAIL, PASSWORD)).isEqualTo("user-1");
    }

    // ── rejection: 401 and 403 are collapsed ──────────────────────────────────────────────────

    @Test
    @DisplayName("a catalogue 401 is an invalid-credentials 401")
    void catalogueUnauthorizedIsInvalidCredentials() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED,
                        "Invalid credentials", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_CREDENTIALS)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("a catalogue 403 (not ACTIVE) is also a 401, so the two are indistinguishable")
    void catalogueForbiddenIsAlsoInvalidCredentials() {
        // The catalogue's 403 reveals the account exists; collapsing it stops that leaking.
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN,
                        "User is not active", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_CREDENTIALS)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.UNAUTHORIZED);
    }

    // ── everything else is an outage, and must NOT become a 401 ───────────────────────────────

    @Test
    @DisplayName("2xx with no userId is a 503 — never a token for the submitted email")
    void successWithoutUserIdIsUnavailable() {
        // Falling back to the submitted email would hand unvalidated input to Keycloak.
        stubResponse("{\"result\":{\"status\":\"ACTIVE\"}}");

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("a 400 for a malformed request is a 503, not a rejection")
    void badRequestIsUnavailable() {
        // A 400 means we sent the wrong shape: a contract fault, not a wrong password.
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST,
                        "Email and password are required", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("a 404 (no Kong route) is a 503, not a rejection")
    void notFoundIsUnavailable() {
        // Exactly what a missing Kong route produces. It must not look like a wrong password.
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.NOT_FOUND,
                        "no Route matched with those values", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("an empty body is a 503")
    void nullBodyIsUnavailable() {
        stubResponse(null);

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("an unreachable catalogue is a 503 — fail closed")
    void unreachableCatalogueIsUnavailable() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("a catalogue 500 is a 503")
    void catalogueServerErrorIsUnavailable() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpServerErrorException.create(HttpStatus.INTERNAL_SERVER_ERROR,
                        "boom", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    // ── the password must never reach a log ────────────────────────────────────────────────────

    @Test
    @DisplayName("the password never appears in a log line")
    void passwordIsNeverLogged() {
        Logger logger = (Logger) LoggerFactory.getLogger(CatalogueServiceImpl.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        // logback-test.xml silences this logger, so without this the assertion would pass vacuously.
        Level original = logger.getLevel();
        logger.setLevel(Level.ALL);
        try {
            when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                    .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST,
                            "bad request: password=" + PASSWORD, null, null, null));

            assertThatThrownBy(() -> service.verifyCredentials(EMAIL, PASSWORD))
                    .isInstanceOf(CustomException.class);

            assertThat(appender.list).isNotEmpty();
            assertThat(appender.list)
                    .as("a log line leaked the password")
                    .noneMatch(event -> event.getFormattedMessage().contains(PASSWORD));
        } finally {
            logger.setLevel(original);
            logger.detachAppender(appender);
        }
    }

    // ── verifyPin ──────────────────────────────────────────────────────────────────────────────

    private static final String PIN = "482913";

    @Test
    @DisplayName("verifyPin posts {userId, pin} to base-url + verify-pin-path")
    void verifyPinPostsToItsOwnPath() {
        stubResponse("{\"result\":{\"userId\":\"user-1\",\"status\":\"ACTIVE\"}}");

        service.verifyPin("user-1", PIN);

        ArgumentCaptor<HttpEntity> request = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(eq(BASE_URL + VERIFY_PIN_PATH), eq(HttpMethod.POST),
                request.capture(), eq(JsonNode.class));
        @SuppressWarnings("unchecked")
        Map<String, String> body = (Map<String, String>) request.getValue().getBody();
        assertThat(body)
                .containsEntry("userId", "user-1")
                .containsEntry("pin", PIN)
                .doesNotContainKey("email");
    }

    @Test
    @DisplayName("a wrong PIN is an invalid-credentials 401, the code the five-strike rule counts")
    void wrongPinIsInvalidCredentials() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED,
                        "Unauthorized", null, null, null));

        assertThatThrownBy(() -> service.verifyPin("user-1", PIN))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_CREDENTIALS);
    }

    @Test
    @DisplayName("a 2xx for a DIFFERENT user is a 503, never a successful PIN")
    void verifyPinForAnotherUserIsUnavailable() {
        stubResponse("{\"result\":{\"userId\":\"user-2\",\"status\":\"ACTIVE\"}}");

        assertThatThrownBy(() -> service.verifyPin("user-1", PIN))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("the PIN never appears in a log line")
    void pinIsNeverLogged() {
        Logger logger = (Logger) LoggerFactory.getLogger(CatalogueServiceImpl.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        Level original = logger.getLevel();
        logger.setLevel(Level.ALL);
        try {
            when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                    .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST,
                            "bad request: pin=" + PIN, null, null, null));

            assertThatThrownBy(() -> service.verifyPin("user-1", PIN)).isInstanceOf(CustomException.class);

            assertThat(appender.list).isNotEmpty();
            assertThat(appender.list)
                    .as("a log line leaked the PIN")
                    .noneMatch(event -> event.getFormattedMessage().contains(PIN));
        } finally {
            logger.setLevel(original);
            logger.detachAppender(appender);
        }
    }
}
