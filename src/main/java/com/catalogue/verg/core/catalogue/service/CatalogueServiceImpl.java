package com.catalogue.verg.core.catalogue.service;

import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Service
public class CatalogueServiceImpl implements CatalogueService {

    private static final String FIELD_RESULT = "result";
    private static final String FIELD_USER_ID = "userId";

    @Autowired
    private VergProperties vergProperties;

    @Autowired
    @Qualifier("catalogueRestTemplate")
    private RestTemplate restTemplate;

    /** Never log the arguments, the request or the response: one carries a plaintext password. */
    @Override
    public String verifyCredentials(String email, String password) {
        // Jackson, not concatenation: a quote in a password would emit broken JSON.
        return post("verifyCredentials", verifyUrl(),
                Map.of(Constants.AUTH_FIELD_EMAIL, email, Constants.AUTH_FIELD_PASSWORD, password));
    }

    /** Same rules as verifyCredentials: never log the PIN or anything that may echo it. */
    @Override
    public void verifyPin(String userId, String pin) {
        String verified = post("verifyPin", verifyPinUrl(),
                Map.of(Constants.AUTH_FIELD_USER_ID, userId, Constants.AUTH_FIELD_PIN, pin));
        if (!userId.equals(verified)) {
            // A 2xx about somebody else is a broken catalogue, not a PIN the user got right.
            log.error("CatalogueServiceImpl::verifyPin: 2xx for a different userId — refusing to issue a token");
            throw unavailable();
        }
    }

    /** Posts a credential check and returns the verified userId: 401/403 -> 401, anything else -> 503. */
    private String post(String operation, String url, Map<String, String> payload) {
        JsonNode body;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, String>> request = new HttpEntity<>(payload, headers);

            body = restTemplate.exchange(url, HttpMethod.POST, request, JsonNode.class).getBody();
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            // 401 bad credential, 403 non-ACTIVE: collapsed so neither can be told apart.
            log.warn("CatalogueServiceImpl::{}: catalogue rejected the credentials", operation);
            throw new CustomException(Constants.AUTH_INVALID_CREDENTIALS,
                    Constants.AUTH_INVALID_CREDENTIALS_MSG, HttpStatus.UNAUTHORIZED);
        } catch (HttpStatusCodeException e) {
            // Status only: getMessage() embeds the response body, which may echo the request.
            log.error("CatalogueServiceImpl::{}: catalogue refused the call (status={})",
                    operation, e.getStatusCode());
            throw unavailable();
        } catch (RestClientException e) {
            // Class name only: the message carries the catalogue's internal host and port.
            log.error("CatalogueServiceImpl::{}: catalogue call failed ({})",
                    operation, e.getClass().getSimpleName());
            throw unavailable();
        }

        // An unreadable 2xx is an outage, not a rejection: a 401 would blame the user's credential.
        String userId = body == null ? null : body.path(FIELD_RESULT).path(FIELD_USER_ID).asText(null);
        if (StringUtils.isBlank(userId)) {
            // Never fall back to anything submitted: it is unvalidated caller input.
            log.error("CatalogueServiceImpl::{}: 2xx with no userId — refusing to issue a token", operation);
            throw unavailable();
        }
        return userId;
    }

    private CustomException unavailable() {
        return new CustomException(Constants.AUTH_UPSTREAM_UNAVAILABLE,
                Constants.AUTH_UPSTREAM_UNAVAILABLE_MSG, HttpStatus.SERVICE_UNAVAILABLE);
    }

    private String verifyUrl() {
        return vergProperties.getCatalogueBaseUrl() + vergProperties.getCatalogueVerifyPath();
    }

    private String verifyPinUrl() {
        return vergProperties.getCatalogueBaseUrl() + vergProperties.getCatalogueVerifyPinPath();
    }
}
