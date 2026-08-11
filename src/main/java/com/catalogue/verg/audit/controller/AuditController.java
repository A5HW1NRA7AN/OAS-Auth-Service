package com.catalogue.verg.audit.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.elasticsearch.dto.SearchCriteria;
import com.catalogue.verg.audit.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/audit")
public class AuditController {
    @Autowired
    private AuditService auditService;

    // @PostMapping("/v1/create")
    public ResponseEntity<CustomResponse> create(@RequestBody JsonNode auditDetails) {
        CustomResponse response = auditService.createAudit(auditDetails);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    @PostMapping("/v1/search")
    public ResponseEntity<?> search(@RequestBody SearchCriteria searchCriteria) {
        CustomResponse response = auditService.searchAudit(searchCriteria);
        return new ResponseEntity<>(response, response.getResponseCode());
    }

    @GetMapping("/v1/read/{id}")
    public ResponseEntity<?> read(@PathVariable String id) {
        CustomResponse response = auditService.read(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    // @DeleteMapping("/v1/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable String id) {
        CustomResponse response = auditService.delete(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    // @PostMapping("/v1/import")
    public ResponseEntity<CustomResponse> importData(@RequestParam("file") MultipartFile file) {
        CustomResponse response = auditService.importData(file);
        return new ResponseEntity<>(response, response.getResponseCode());
    }
}