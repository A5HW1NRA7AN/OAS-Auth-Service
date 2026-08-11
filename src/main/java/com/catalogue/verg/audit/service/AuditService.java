package com.catalogue.verg.audit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.elasticsearch.dto.SearchCriteria;
import org.springframework.web.multipart.MultipartFile;


public interface AuditService {

    CustomResponse createAudit(JsonNode auditEntity);

    CustomResponse searchAudit(SearchCriteria searchCriteria);

    CustomResponse assignAudit(JsonNode auditEntity, String token);

    CustomResponse read(String id);

    CustomResponse delete(String id);

    CustomResponse importData(MultipartFile file);
}