package com.catalogue.verg.auth.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.elasticsearch.dto.SearchCriteria;
import com.catalogue.verg.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/v1/create")
    public ResponseEntity<CustomResponse> create(@RequestBody JsonNode authDetails) {
        CustomResponse response = authService.createAuth(authDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    // Issues a token for the credentials in the payload
    @PostMapping("/v1/auth_token_create")
    public ResponseEntity<CustomResponse> authTokenCreate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenCreate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    // Verifies the token in the payload and returns its claims
    @PostMapping("/v1/auth_token_validate")
    public ResponseEntity<CustomResponse> authTokenValidate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenValidate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    // Revokes the token in the payload so it can no longer be used
    @PostMapping("/v1/auth_token_invalidate")
    public ResponseEntity<CustomResponse> authTokenInvalidate(@RequestBody JsonNode tokenDetails) {
        CustomResponse response = authService.authTokenInvalidate(tokenDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    @PostMapping("/v1/search")
    public ResponseEntity<?> search(@RequestBody SearchCriteria searchCriteria) {
        CustomResponse response = authService.searchAuth(searchCriteria);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    @GetMapping("/v1/read/{id}")
    public ResponseEntity<?> read(@PathVariable String id) {
        CustomResponse response = authService.read(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PutMapping("/v1/update/{id}")
    public ResponseEntity<CustomResponse> update(@PathVariable String id, @RequestBody JsonNode authDetails) {
        CustomResponse response = authService.updateAuth(id, authDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    @DeleteMapping("/v1/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable String id) {
        CustomResponse response = authService.delete(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/import")
    public ResponseEntity<CustomResponse> importData(@RequestParam("file") MultipartFile file) {
        CustomResponse response = authService.importData(file);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    // Drops the ES index and rebuilds it from the primary store (Postgres); skips DELETED records
    @PostMapping("/v1/loadFromPrimary")
    public ResponseEntity<CustomResponse> loadFromPrimary() {
        CustomResponse response = authService.loadFromPrimaryAuth();
        return new ResponseEntity<>(response, response.getResponseCode());
    }
}
