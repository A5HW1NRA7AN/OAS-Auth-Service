package com.catalogue.verg.core.catalogue.service;

import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.VergProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
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
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Service
public class CatalogueServiceImpl implements CatalogueService {

    private static final String FIELD_RESULT = "result";
    private static final String FIELD_VALID = "valid";
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
            HttpEntity<Map<String, String>> request = new HttpEntity<>(
                    Map.of(Constants.AUTH_FIELD_USERNAME, username,
                            Constants.AUTH_FIELD_PASSWORD, password),
                    headers);

            body = restTemplate.exchange(verifyUrl(), HttpMethod.POST, request, JsonNode.class).getBody();
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

        // The catalogue's own handlers disagree: create/update put the payload flat at `result`,
        // read/search nest it at `result.result`. Prefer flat, accept nested, never guess the verdict.
        JsonNode result = body == null ? MissingNode.getInstance() : body.path(FIELD_RESULT);
        JsonNode verdict = result.has(FIELD_VALID) ? result : result.path(FIELD_RESULT);
        JsonNode valid = verdict.path(FIELD_VALID);

        if (valid.isMissingNode() || valid.isNull()) {
            // Not a "no": a 401 here would blame the user's password during a catalogue outage and
            // hide the outage. That repo answers 200 for NOT_FOUND, so this shape is likely.
            log.error("CatalogueServiceImpl::verifyCredentials: no `{}` in the catalogue response — "
                    + "treating as unavailable, not as a rejection", FIELD_VALID);
            throw unavailable();
        }
        if (!valid.asBoolean(false)) {
            // One outcome for unknown user, wrong password and non-ACTIVE — anything else enumerates.
            log.warn("CatalogueServiceImpl::verifyCredentials: catalogue rejected the credentials");
            throw new CustomException(Constants.AUTH_INVALID_CREDENTIALS,
                    Constants.AUTH_INVALID_CREDENTIALS_MSG, HttpStatus.UNAUTHORIZED);
        }

        String userId = verdict.path(FIELD_USER_ID).asText();
        if (StringUtils.isBlank(userId)) {
            // Never fall back to the submitted username: it is unvalidated caller input.
            log.error("CatalogueServiceImpl::verifyCredentials: valid:true with no userId — "
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
