package com.catalogue.verg.core.util;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Application tunables bound from the environment. Client connection settings live in the relevant
 * {@code config} class; this holds the values the service logic reads.
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

    /** true (default): the catalogue verifies the password. false: auth_token_create trusts its caller. */
    @Value("${catalogue.validate-enabled}")
    private boolean catalogueValidateEnabled;

    /** In-cluster Service DNS. Never the public host — this call carries a plaintext password. */
    @Value("${catalogue.base-url}")
    private String catalogueBaseUrl;

    @Value("${catalogue.verify-path}")
    private String catalogueVerifyPath;
}
