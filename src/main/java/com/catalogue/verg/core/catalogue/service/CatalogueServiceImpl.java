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
    public String verifyCredentials(String username, String password) {
        JsonNode body;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            // Jackson, not string concatenation: a quote or backslash in a password would otherwise
            // emit broken JSON and lock that user out permanently.
            // The catalogue's field is `email`. Ours stays `username` — whatever the user typed —
            // so it keeps working if the catalogue later resolves a userId here too.
            HttpEntity<Map<String, String>> request = new HttpEntity<>(
                    Map.of(Constants.AUTH_FIELD_EMAIL, username,
                            Constants.AUTH_FIELD_PASSWORD, password),
                    headers);

            body = restTemplate.exchange(verifyUrl(), HttpMethod.POST, request, JsonNode.class).getBody();
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            // 401 is a bad credential, 403 is a non-ACTIVE account. Collapsed on purpose so a caller
            // cannot tell a blocked account from a wrong password.
            log.warn("CatalogueServiceImpl::verifyCredentials: catalogue rejected the credentials");
            throw new CustomException(Constants.AUTH_INVALID_CREDENTIALS,
                    Constants.AUTH_INVALID_CREDENTIALS_MSG, HttpStatus.UNAUTHORIZED);
        } catch (HttpStatusCodeException e) {
            // Status only: getMessage() embeds the response body, which may echo the request.
            log.error("CatalogueServiceImpl::verifyCredentials: catalogue refused the call (status={})",
                    e.getStatusCode());
            throw unavailable();
        } catch (RestClientException e) {
            // Class name only: the message carries the catalogue's internal host and port.
            log.error("CatalogueServiceImpl::verifyCredentials: catalogue call failed ({})",
                    e.getClass().getSimpleName());
            throw unavailable();
        }

        // A rejection already threw above, so reaching here means 2xx: success is a userId, flat at
        // `result`. Anything else is an outage, not a rejection — reporting 401 for an unreadable
        // response would blame the user's password and hide the fault.
        String userId = body == null ? null : body.path(FIELD_RESULT).path(FIELD_USER_ID).asText(null);
        if (StringUtils.isBlank(userId)) {
            // Never fall back to the submitted username: it is unvalidated caller input.
            log.error("CatalogueServiceImpl::verifyCredentials: 2xx with no userId — "
                    + "refusing to issue a token");
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
}
