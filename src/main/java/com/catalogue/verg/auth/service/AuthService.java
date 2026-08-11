package com.catalogue.verg.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.elasticsearch.dto.SearchCriteria;
import org.springframework.web.multipart.MultipartFile;


public interface AuthService {

    CustomResponse createAuth(JsonNode authEntity);

    CustomResponse updateAuth(String id, JsonNode authEntity);

    // Issues a token for the credentials in the payload
    CustomResponse authTokenCreate(JsonNode tokenDetails);

    // Verifies the token in the payload and returns its claims
    CustomResponse authTokenValidate(JsonNode tokenDetails);

    // Revokes the token in the payload so it can no longer be used
    CustomResponse authTokenInvalidate(JsonNode tokenDetails);

    CustomResponse searchAuth(SearchCriteria searchCriteria);

    CustomResponse assignAuth(JsonNode authEntity, String token);

    CustomResponse read(String id);

    CustomResponse delete(String id);

    CustomResponse importData(MultipartFile file);

    // Drops the ES index and rebuilds it from the primary store (Postgres); skips DELETED records
    CustomResponse loadFromPrimaryAuth();
}
