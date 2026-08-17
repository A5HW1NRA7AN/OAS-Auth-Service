package com.catalogue.verg.core.util;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Application tunables, bound from the environment.
 *
 * <p>Connection settings used to build clients live in the relevant {@code config} class
 * (see {@code core/keycloak/config/KeycloakConfig}); this holds the values the service logic reads.
 */
@Component
@Getter
@Setter
public class VergProperties {

    /** What Keycloak stamps into {@code iss}. Separate from the URL we call it on. */
    @Value("${keycloak.issuer}")
    private String keycloakIssuer;

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${keycloak.client-id}")
    private String keycloakClientId;

    @Value("${keycloak.client-secret}")
    private String keycloakClientSecret;

    /** Tolerance for machines whose clocks disagree. */
    @Value("${keycloak.clock-skew-seconds}")
    private long keycloakClockSkewSeconds;

    /** Must be >= the realm's access token lifespan, or revoked tokens outlive their entry. */
    @Value("${keycloak.denylist-sid-ttl-seconds}")
    private long keycloakDenylistSidTtlSeconds;
}
