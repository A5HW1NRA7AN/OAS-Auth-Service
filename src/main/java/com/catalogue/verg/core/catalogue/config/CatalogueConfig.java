package com.catalogue.verg.core.catalogue.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/** The client used to talk to the user-catalogue. */
@Configuration
public class CatalogueConfig {

    @Value("${catalogue.connect-timeout-ms}")
    private int connectTimeoutMs;

    @Value("${catalogue.read-timeout-ms}")
    private int readTimeoutMs;

    /** Verification fails closed, so a hung catalogue is an auth outage. Short setters are Boot 3.4+. */
    @Bean
    public RestTemplate catalogueRestTemplate() {
        return new RestTemplateBuilder()
                .setConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .setReadTimeout(Duration.ofMillis(readTimeoutMs))
                .build();
    }
}
