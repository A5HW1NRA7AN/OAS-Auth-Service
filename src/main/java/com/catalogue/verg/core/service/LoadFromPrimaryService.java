package com.catalogue.verg.core.service;

import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.elasticsearch.service.ESUtilService;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Generic service that rebuilds an entity's Elasticsearch index from the primary store (Postgres).
 * <p>
 * Each entity's ServiceImpl delegates to this service, passing its index name, ES field-whitelist
 * path, the full list of Postgres records, and functions describing how to extract each record's id,
 * build its ES document projection, and decide whether it should be indexed.
 * <p>
 * The whole index is dropped first, then every record satisfying {@code shouldIndex} is re-added.
 * Elasticsearch auto-recreates the index (dynamic mapping) on the first document insert, mirroring how
 * the index is created during normal create operations. Supports partial-success: per-record failures
 * are collected and reported without aborting the run.
 *
 * @see ImportService for the analogous per-entity delegation pattern.
 */
@Slf4j
@Service
public class LoadFromPrimaryService {

    @Autowired
    private ESUtilService esUtilService;

    /**
     * Drops {@code indexName} and loads every record from the primary store for which
     * {@code shouldIndex} is true.
     *
     * @param indexName       the Elasticsearch index to rebuild
     * @param jsonPath        classpath path to the entity's ES required-fields whitelist JSON
     * @param records         all Postgres records for the entity (e.g. repository.findAll())
     * @param idExtractor     maps a record to its Elasticsearch document id
     * @param documentBuilder maps a record to its Elasticsearch document (the ES/Redis projection)
     * @param shouldIndex     records failing this predicate are skipped (e.g. DELETED soft-deletes)
     * @param <T>             the entity type
     */
    public <T> CustomResponse loadFromPrimary(
            String indexName,
            String jsonPath,
            List<T> records,
            Function<T, String> idExtractor,
            Function<T, Map<String, Object>> documentBuilder,
            Predicate<T> shouldIndex) {

        log.info("LoadFromPrimaryService::loadFromPrimary::started for index: {}", indexName);
        CustomResponse response = new CustomResponse();

        // Drop the whole index first; auto-recreated on the first addDocument below.
        try {
            esUtilService.deleteIndex(indexName);
        } catch (Exception e) {
            throw new CustomException("LOAD_FROM_PRIMARY_ERROR",
                    "Failed to reset index " + indexName + ": " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }

        int totalRecords = records == null ? 0 : records.size();
        int indexedCount = 0;
        int skippedCount = 0;
        List<Map<String, Object>> failedRecords = new ArrayList<>();

        if (records != null) {
            for (T record : records) {
                String id = null;
                try {
                    if (!shouldIndex.test(record)) {
                        skippedCount++;
                        continue;
                    }
                    id = idExtractor.apply(record);
                    Map<String, Object> document = documentBuilder.apply(record);
                    esUtilService.addDocument(indexName, Constants.INDEX_TYPE, id, document, jsonPath);
                    indexedCount++;
                } catch (Exception e) {
                    log.error("LoadFromPrimaryService::loadFromPrimary::failed for id {} in index {}", id, indexName, e);
                    Map<String, Object> failure = new HashMap<>();
                    failure.put("id", id);
                    failure.put("errors", e.getMessage());
                    failedRecords.add(failure);
                }
            }
        }

        int failedCount = failedRecords.size();
        response.getResult().put("indexName", indexName);
        response.getResult().put("totalRecords", totalRecords);
        response.getResult().put("indexedCount", indexedCount);
        response.getResult().put("skippedCount", skippedCount);
        response.getResult().put("failedCount", failedCount);
        response.getResult().put("failedRecords", failedRecords);

        if (failedCount == 0) {
            response.setMessage("Load from primary completed");
            response.setResponseCode(HttpStatus.OK);
        } else if (indexedCount == 0) {
            response.setMessage("Load from primary failed - all records failed to index");
            response.setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR);
        } else {
            response.setMessage("Load from primary completed with some errors");
            response.setResponseCode(HttpStatus.OK);
        }

        log.info("LoadFromPrimaryService::loadFromPrimary::completed for index {}: total={}, indexed={}, skipped={}, failed={}",
                indexName, totalRecords, indexedCount, skippedCount, failedCount);
        return response;
    }
}
