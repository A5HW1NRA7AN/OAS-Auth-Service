package com.catalogue.verg.core.keycloak.config;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Builds the clients used to talk to Keycloak.
 */
@Configuration
public class KeycloakConfig {

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${keycloak.connect-timeout-ms}")
    private int connectTimeoutMs;

    @Value("${keycloak.read-timeout-ms}")
    private int readTimeoutMs;

    /**
     * A dedicated RestTemplate with timeouts. Spring supplies no timeouts by default, so a hung
     * Keycloak would hold the request thread indefinitely.
     *
     * <p>setConnectTimeout/setReadTimeout, not the shorter names — those are Spring Boot 3.4+.
     */
    @Bean
    public RestTemplate keycloakRestTemplate() {
        return new RestTemplateBuilder()
                .setConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .setReadTimeout(Duration.ofMillis(readTimeoutMs))
                .build();
    }

    /**
     * Supplies Keycloak's public signing keys, so tokens can be verified without calling Keycloak.
     *
     * <p>Caching survives Keycloak's key rotation without an application restart; the rate limit
     * stops tokens carrying made-up {@code kid} values from becoming a flood of outbound requests.
     */
    @Bean
    public JwkProvider jwkProvider() {
        String jwksUrl = keycloakBaseUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs";
        try {
            return new JwkProviderBuilder(URI.create(jwksUrl).toURL())
                    .cached(10, 24, TimeUnit.HOURS)
                    .rateLimited(10, 1, TimeUnit.MINUTES)
                    .build();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid Keycloak JWKS URL: " + jwksUrl, e);
        }
    }
}
