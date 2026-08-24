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

/** Builds the clients used to talk to Keycloak. */
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
     * Dedicated RestTemplate with timeouts: Spring supplies none, so a hung Keycloak would hold the
     * request thread indefinitely. The long setter names are required below Boot 3.4.
     */
    @Bean
    public RestTemplate keycloakRestTemplate() {
        return new RestTemplateBuilder()
                .setConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .setReadTimeout(Duration.ofMillis(readTimeoutMs))
                .build();
    }

    /**
     * Supplies Keycloak's signing keys so tokens verify without calling it. The cache is keyed by
     * kid, so a rotated key is simply a miss; the rate limit caps forged-kid lookups.
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
