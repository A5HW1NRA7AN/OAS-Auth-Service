package com.catalogue.verg.auth.service;

import com.catalogue.verg.core.dto.CustomResponse;
import com.fasterxml.jackson.databind.JsonNode;

public interface AuthService {

    CustomResponse authTokenCreate(JsonNode tokenDetails);

    CustomResponse authTokenValidate(JsonNode tokenDetails);

    CustomResponse authTokenInvalidate(JsonNode tokenDetails);

    CustomResponse authUserRevoke(JsonNode userDetails);
}
