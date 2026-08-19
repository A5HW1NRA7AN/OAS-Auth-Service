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

/**
 * The credential check. Every test is the same assertion: no token unless the catalogue said
 * valid:true AND gave a userId. The interesting cases are the ones a naive impl would call 401.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CatalogueServiceImplTest {

    private static final String BASE_URL = "http://localhost:8082";
    private static final String VERIFY_PATH = "/user/v1/verify";
    private static final String USERNAME = "asha@example.org";
    private static final String PASSWORD = "Sup3r-S3cret!";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CatalogueServiceImpl service = new CatalogueServiceImpl();

    @Mock
    private RestTemplate restTemplate;

    CatalogueServiceImplTest() {
        VergProperties props = new VergProperties();
        props.setCatalogueBaseUrl(BASE_URL);
        props.setCatalogueVerifyPath(VERIFY_PATH);
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

    // ── the happy paths ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("posts the credentials to base-url + verify-path, verbatim")
    void postsCredentialsToConfiguredUrl() {
        stubResponse("{\"result\":{\"valid\":true,\"userId\":\"user-1\"}}");

        service.verifyCredentials(USERNAME, PASSWORD);

        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(eq(BASE_URL + VERIFY_PATH), eq(HttpMethod.POST),
                captor.capture(), eq(JsonNode.class));
        @SuppressWarnings("unchecked")
        Map<String, String> body = (Map<String, String>) captor.getValue().getBody();
        // Untrimmed: a password is bytes, not a name.
        assertThat(body).containsEntry("username", USERNAME).containsEntry("password", PASSWORD);
    }

    @Test
    @DisplayName("valid:true flat at result returns the catalogue's userId")
    void validTrueFlatReturnsUserId() {
        stubResponse("{\"result\":{\"valid\":true,\"userId\":\"user-1\"}}");

        assertThat(service.verifyCredentials(USERNAME, PASSWORD)).isEqualTo("user-1");
    }

    @Test
    @DisplayName("valid:true nested at result.result also works")
    void validTrueNestedReturnsUserId() {
        // That repo's read/search handlers nest one level deeper than create/update.
        stubResponse("{\"result\":{\"result\":{\"valid\":true,\"userId\":\"user-1\"}}}");

        assertThat(service.verifyCredentials(USERNAME, PASSWORD)).isEqualTo("user-1");
    }

    // ── rejection ──────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("valid:false is a 401, and the only outcome that is")
    void validFalseIsUnauthorized() {
        stubResponse("{\"result\":{\"valid\":false}}");

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_INVALID_CREDENTIALS)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.UNAUTHORIZED);
    }

    // ── the cases that must NOT become a 401, and must NOT issue a token ───────────────────────

    @Test
    @DisplayName("valid:true with no userId is a 503 — never a token for the submitted username")
    void validTrueWithoutUserIdIsUnavailable() {
        // The tempting fallback — "use the username we were given" — would feed unvalidated caller
        // input to Keycloak as a username.
        stubResponse("{\"result\":{\"valid\":true}}");

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE)
                .hasFieldOrPropertyWithValue("httpStatusCode", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("the catalogue's error envelope at HTTP 200 is a 503, not a 401")
    void errorEnvelopeAtHttp200IsUnavailable() {
        // That repo answers 200 for NOT_FOUND. A 401 here would blame the password and hide an outage.
        stubResponse("{\"code\":\"Validation Error\",\"message\":\"...\",\"httpStatusCode\":404}");

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("a response with no valid field is a 503")
    void missingValidFieldIsUnavailable() {
        stubResponse("{\"result\":{}}");

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("valid:null is a 503, not a rejection")
    void nullValidIsUnavailable() {
        stubResponse("{\"result\":{\"valid\":null}}");

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("an empty body is a 503")
    void nullBodyIsUnavailable() {
        stubResponse(null);

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("an unreachable catalogue is a 503 — fail closed")
    void unreachableCatalogueIsUnavailable() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("a catalogue 500 is a 503")
    void catalogueServerErrorIsUnavailable() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpServerErrorException.create(HttpStatus.INTERNAL_SERVER_ERROR,
                        "boom", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
                .isInstanceOf(CustomException.class)
                .hasFieldOrPropertyWithValue("code", Constants.AUTH_UPSTREAM_UNAVAILABLE);
    }

    @Test
    @DisplayName("a catalogue 401 is a 503, not passed through as a rejection")
    void catalogueUnauthorizedIsUnavailable() {
        // A 401 means OUR call was refused (e.g. base-url is the public host), not a bad password.
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED,
                        "unauthorized", null, null, null));

        assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
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

            assertThatThrownBy(() -> service.verifyCredentials(USERNAME, PASSWORD))
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
}
