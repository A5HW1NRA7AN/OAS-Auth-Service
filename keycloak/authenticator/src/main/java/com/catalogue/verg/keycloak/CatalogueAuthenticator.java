package com.catalogue.verg.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.CredentialRepresentation;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Validates Direct Grant passwords against the OAS user-catalogue instead of Keycloak's own
 * credential store, so credential material lives in exactly one database.
 *
 * <p>Replaces only the password step. The built-in {@code direct-grant-validate-username} still
 * runs first, so Keycloak resolves the user and enforces the {@code enabled} flag before this code
 * — {@code context.getUser()} is already populated here.
 *
 * <p>Failures go through {@code context.failure(...)} rather than exceptions, because Keycloak's
 * brute-force protection is driven off authentication-flow failures.
 */
public class CatalogueAuthenticator extends AbstractDirectGrantAuthenticator {

    private static final Logger log = Logger.getLogger(CatalogueAuthenticator.class);

    public static final String PROVIDER_ID = "catalogue-validate-password";

    static final String CONF_URL = "catalogueUrl";
    static final String CONF_CONNECT_TIMEOUT = "connectTimeoutMs";
    static final String CONF_READ_TIMEOUT = "readTimeoutMs";

    /**
     * Fallback only — setup-realm.sh always sets `catalogueUrl` explicitly. Resolved from inside the
     * Keycloak container, so never plain localhost: `host.docker.internal` locally, a Service name
     * (e.g. http://user-catalogue:8080) in Kubernetes.
     */
    private static final String DEFAULT_URL = "http://host.docker.internal:8082";
    private static final String VERIFY_PATH = "/user/v1/verify_credentials";
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 2000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 5000;

    /** One message for every rejection — the catalogue already refuses to say which check failed. */
    private static final String GENERIC_ERROR = "Invalid user credentials";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            fail(context, null);
            return;
        }

        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String password = form.getFirst(CredentialRepresentation.PASSWORD);
        if (password == null || password.isEmpty()) {
            fail(context, user);
            return;
        }

        CatalogueConfig cfg = readConfig(context);
        try {
            if (!verifyWithCatalogue(cfg, user.getUsername(), password)) {
                fail(context, user);
                return;
            }
        } catch (Exception e) {
            // Fail closed: treating an outage as a successful login is a total auth bypass.
            log.errorf(e, "catalogue verification failed for %s; rejecting", user.getUsername());
            context.getEvent().user(user);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    errorResponse(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(),
                            "temporarily_unavailable", "Authentication is temporarily unavailable"));
            return;
        }

        context.success();
    }

    /** @throws Exception if the catalogue could not be reached. */
    private boolean verifyWithCatalogue(CatalogueConfig cfg, String username, String password) throws Exception {
        // Hand-built JSON so this jar needs no JSON library on Keycloak's classpath.
        String body = "{\"username\":" + jsonString(username) + ",\"password\":" + jsonString(password) + "}";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(cfg.url() + VERIFY_PATH))
                .timeout(Duration.ofMillis(cfg.readTimeoutMs()))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(cfg.connectTimeoutMs()))
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IllegalStateException("catalogue returned HTTP " + response.statusCode());
        }
        return response.body().replaceAll("\\s+", "").contains("\"valid\":true");
    }

    private static String jsonString(String raw) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : raw.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(c < 0x20 ? String.format("\\u%04x", (int) c) : c);
            }
        }
        return sb.append('"').toString();
    }

    private void fail(AuthenticationFlowContext context, UserModel user) {
        if (user != null) {
            context.getEvent().user(user);
        }
        // Errors.INVALID_USER_CREDENTIALS is the event code; the flow enum calls it
        // INVALID_CREDENTIALS. Reporting both is what lets brute-force protection count this.
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", GENERIC_ERROR));
    }

    private record CatalogueConfig(String url, int connectTimeoutMs, int readTimeoutMs) {
        CatalogueConfig {
            if (url == null || url.isBlank()) {
                url = DEFAULT_URL;
            }
            url = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        }
    }

    private CatalogueConfig readConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel model = context.getAuthenticatorConfig();
        Map<String, String> c = model == null ? Map.of() : model.getConfig();
        return new CatalogueConfig(c.getOrDefault(CONF_URL, DEFAULT_URL),
                parseInt(c.get(CONF_CONNECT_TIMEOUT), DEFAULT_CONNECT_TIMEOUT_MS),
                parseInt(c.get(CONF_READ_TIMEOUT), DEFAULT_READ_TIMEOUT_MS));
    }

    private static int parseInt(String value, int fallback) {
        try {
            return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Direct grant is a single request/response.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Password management belongs to the catalogue.
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Catalogue Password Validation";
    }

    @Override
    public String getReferenceCategory() {
        return "password";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates the password against the OAS user-catalogue. Keycloak stores no password.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                property(CONF_URL, "Catalogue base URL", DEFAULT_URL,
                        "Must be reachable from inside the Keycloak container"),
                property(CONF_CONNECT_TIMEOUT, "Connect timeout (ms)",
                        String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS), null),
                property(CONF_READ_TIMEOUT, "Read timeout (ms)",
                        String.valueOf(DEFAULT_READ_TIMEOUT_MS), null));
    }

    private static ProviderConfigProperty property(String name, String label, String def, String help) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setType(ProviderConfigProperty.STRING_TYPE);
        p.setDefaultValue(def);
        if (help != null) {
            p.setHelpText(help);
        }
        return p;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
