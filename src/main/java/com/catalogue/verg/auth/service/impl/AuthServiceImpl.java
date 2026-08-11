package com.catalogue.verg.auth.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.datastax.oss.driver.api.core.uuid.Uuids;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.catalogue.verg.core.cache.CacheService;
import com.catalogue.verg.core.dto.CustomResponse;
import com.catalogue.verg.core.dto.RespParam;
import com.catalogue.verg.core.elasticsearch.dto.SearchCriteria;
import com.catalogue.verg.core.elasticsearch.dto.SearchResult;
import com.catalogue.verg.core.elasticsearch.service.ESUtilService;
import com.catalogue.verg.core.exception.CustomException;
import com.catalogue.verg.core.util.Constants;
import com.catalogue.verg.core.util.PayloadValidation;
import com.catalogue.verg.core.util.VergProperties;
import com.catalogue.verg.core.service.AuditLogService;
import com.catalogue.verg.core.service.ImportService;
import com.catalogue.verg.core.service.LoadFromPrimaryService;
import com.catalogue.verg.core.util.PrimaryKeyUtil;
import com.catalogue.verg.auth.entity.AuthEntity;
import com.catalogue.verg.auth.repository.AuthRepository;
import com.catalogue.verg.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import org.springframework.web.multipart.MultipartFile;

import java.sql.Timestamp;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


@Service
@Slf4j
public class AuthServiceImpl implements AuthService {
    @Autowired
    private PayloadValidation payloadValidation;

    @Autowired
    private PrimaryKeyUtil primaryKeyUtil;

    @Autowired
    private AuthRepository authRepository;

    @Autowired
    private ESUtilService esUtilService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CacheService cacheService;

    @Autowired
    private RedisTemplate<String, SearchResult> redisTemplate;

    @Autowired
    private VergProperties vergProperties;

    @Autowired
    private ImportService importService;

    @Autowired
    private LoadFromPrimaryService loadFromPrimaryService;

    @Autowired
    private AuditLogService auditLogService;

    /** Catalogue name recorded on every audit row emitted by this service. */
    private static final String AUDIT_ENTITY_NAME = "auth";

    private Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Value("${spring.redis.cacheTtl}")
    private long searchResultRedisTtl;

    @Override
    public CustomResponse createAuth(JsonNode authEntity) {
        log.info("AuthServiceImpl::createAuth:entered the method: " + authEntity);
        CustomResponse response = new CustomResponse();
        payloadValidation.validatePayload(Constants.AUTH_VALIDATION_FILE_JSON, authEntity);

        log.debug("AuthServiceImpl::createAuth:validated the payload");
        try {
            log.info("AuthServiceImpl::createAuth:creating auth");
            AuthEntity authEntity1 = new AuthEntity();
            // Generate Primary Key
            String primaryID = primaryKeyUtil.generateKey(Constants.AUTH_VALIDATION_FILE_JSON);
            authEntity1.setAuthId(primaryID);
            // Create Parameters like createdDate / updateDate / Data and Status
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());
            authEntity1.setCreatedOn(currentTime);
            authEntity1.setUpdatedOn(currentTime);
            authEntity1.setStatus(Constants.PENDING);
            authEntity1.setData(authEntity);

            authRepository.save(authEntity1);

            log.info("AuthServiceImpl::createAuth::persisted auth in postgres");
            ObjectNode jsonNode = buildDocument(authEntity, Constants.PENDING, currentTime, currentTime);
            Map<String, Object> map = objectMapper.convertValue(jsonNode, Map.class);
            esUtilService.addDocument(Constants.AUTH_INDEX_NAME, Constants.INDEX_TYPE,
                    String.valueOf(primaryID), map, vergProperties.getElasticAuthJsonPath());
            cacheService.putCache(primaryID, jsonNode);
            response.setMessage(Constants.SUCCESSFULLY_CREATED);
            map.put(Constants.AUTH_ID_RQST, primaryID);
            response.setResult(map);
            response.setResponseCode(HttpStatus.OK);
            log.info("AuthServiceImpl::createAuth::persisted auth in OAS");
            auditLogService.logAudit(primaryID, AUDIT_ENTITY_NAME, "create", Constants.PENDING,
                    objectMapper.createObjectNode(), authEntity,
                    authEntity1.getCreatedOn(), authEntity1.getUpdatedOn());
            return response;

        } catch (Exception e) {
            throw new CustomException("error while processing", e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public CustomResponse authTokenCreate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenCreate:entered the method");
        // TODO: authenticate the credentials in the payload and issue a token.
        return notImplemented("authTokenCreate");
    }

    @Override
    public CustomResponse authTokenValidate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenValidate:entered the method");
        // TODO: verify the token signature/expiry and return its claims.
        return notImplemented("authTokenValidate");
    }

    @Override
    public CustomResponse authTokenInvalidate(JsonNode tokenDetails) {
        log.info("AuthServiceImpl::authTokenInvalidate:entered the method");
        // TODO: revoke the token so subsequent validate calls reject it.
        return notImplemented("authTokenInvalidate");
    }

    /** Placeholder response for endpoints whose business logic is not written yet. */
    private CustomResponse notImplemented(String operation) {
        CustomResponse response = new CustomResponse();
        response.setMessage(operation + " is not implemented yet");
        response.setResponseCode(HttpStatus.NOT_IMPLEMENTED);
        return response;
    }

    @Override
    public CustomResponse searchAuth(SearchCriteria searchCriteria) {
        log.info("AuthServiceImpl::searchAuth");
        CustomResponse response = new CustomResponse();
        SearchResult searchResult = redisTemplate.opsForValue()
                .get(generateRedisJwtTokenKey(searchCriteria));
        if (searchResult != null) {
            log.info("AuthServiceImpl::searchAuth: auth search result fetched from redis");
            response.getResult().put(Constants.RESULT, searchResult);
            createSuccessResponse(response);
            auditLogService.logAudit(null, AUDIT_ENTITY_NAME, "search", null, null,
                    objectMapper.valueToTree(searchResult), null, null);
            return response;
        }
        String searchString = searchCriteria.getSearchString();
        if (searchString != null && searchString.length() < 2) {
            createErrorResponse(response, "Minimum 3 characters are required to search",
                    HttpStatus.BAD_REQUEST,
                    Constants.FAILED_CONST);
            return response;
        }
        try {
            searchResult =
                    esUtilService.searchDocuments(Constants.AUTH_INDEX_NAME, searchCriteria);
            response.getResult().put(Constants.RESULT, searchResult);
            createSuccessResponse(response);
            auditLogService.logAudit(null, AUDIT_ENTITY_NAME, "search", null, null,
                    objectMapper.valueToTree(searchResult), null, null);
            return response;
        } catch (Exception e) {
            createErrorResponse(response, e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR,
                    Constants.FAILED_CONST);
            redisTemplate.opsForValue()
                    .set(generateRedisJwtTokenKey(searchCriteria), searchResult, searchResultRedisTtl,
                            TimeUnit.SECONDS);
            return response;
        }
    }

    @Override
    public CustomResponse assignAuth(JsonNode authEntity, String token) {
        return null;
    }

    @Override
    public CustomResponse read(String id) {
        log.info("AuthServiceImpl::read:inside the method");
        CustomResponse response = new CustomResponse();
        if (StringUtils.isEmpty(id)) {
            response.setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR);
            response.setMessage(Constants.ID_NOT_FOUND);
            return response;
        }
        JsonNode auditAfter = null;
        Timestamp auditCreatedOn = null;
        Timestamp auditUpdatedOn = null;
        try {
            String cachedJson = cacheService.getCache(id);
            if (StringUtils.isNotEmpty(cachedJson)) {
                log.info("AuthServiceImpl::read:Record coming from redis cache");
                response.setMessage(Constants.SUCCESSFULLY_READING);
                response
                        .getResult()
                        .put(Constants.RESULT, objectMapper.readValue(cachedJson, new TypeReference<Object>() {
                        }));
                auditAfter = objectMapper.readTree(cachedJson);
            } else {
                Optional<AuthEntity> entityOptional = authRepository.findById(id);
                if (entityOptional.isPresent()) {
                    AuthEntity authEntity = entityOptional.get();
                    ObjectNode jsonNode = buildDocument(authEntity.getData(),
                            authEntity.getStatus(), authEntity.getCreatedOn(),
                            authEntity.getUpdatedOn());
                    cacheService.putCache(id, jsonNode);
                    log.info("AuthServiceImpl::read:Record coming from postgres db");
                    response.setMessage(Constants.SUCCESSFULLY_READING);
                    response
                            .getResult()
                            .put(Constants.RESULT,
                                    objectMapper.convertValue(
                                            jsonNode, new TypeReference<Object>() {
                                            }));
                    auditAfter = jsonNode;
                    auditCreatedOn = authEntity.getCreatedOn();
                    auditUpdatedOn = authEntity.getUpdatedOn();
                } else {
                    response.setResponseCode(HttpStatus.NOT_FOUND);
                    response.setMessage(Constants.INVALID_ID);
                }
            }
        } catch (Exception e) {
            throw new CustomException(Constants.ERROR, "error while processing",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
        if (auditAfter != null) {
            auditLogService.logAudit(null, AUDIT_ENTITY_NAME, "read", null, null, auditAfter,
                    auditCreatedOn, auditUpdatedOn);
        }
        return response;
    }

    @Override
    public CustomResponse updateAuth(String id, JsonNode authEntity) {
        log.info("AuthServiceImpl::updateAuth:entered the method with id: {}", id);
        CustomResponse response = new CustomResponse();

        // Validate that the ID is not null or empty
        if (StringUtils.isEmpty(id)) {
            log.warn("AuthServiceImpl::updateAuth:id is null or empty");
            response.setResponseCode(HttpStatus.BAD_REQUEST);
            response.setMessage(Constants.ID_NOT_FOUND);
            return response;
        }

        // Validate the incoming payload against the entity schema (same as create)
        payloadValidation.validatePayload(Constants.AUTH_VALIDATION_FILE_JSON, authEntity);
        log.debug("AuthServiceImpl::updateAuth:validated the payload");

        try {
            // Check if the entity exists in the database
            Optional<AuthEntity> entityOptional = authRepository.findById(id);
            if (entityOptional.isEmpty()) {
                log.warn("AuthServiceImpl::updateAuth:no record found for id: {}", id);
                response.setResponseCode(HttpStatus.NOT_FOUND);
                response.setMessage(Constants.INVALID_ID);
                return response;
            }

            AuthEntity authEntity1 = entityOptional.get();

            // Reject updates on soft-deleted (DELETED) records
            if (Constants.DELETED.equals(authEntity1.getStatus())) {
                log.warn("AuthServiceImpl::updateAuth:record already deleted for id: {}", id);
                response.setResponseCode(HttpStatus.BAD_REQUEST);
                response.setMessage("Record is already deleted");
                return response;
            }

            // Replace payload; preserve id / createdOn / status, bump updatedOn
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());
            authEntity1.setData(authEntity);
            authEntity1.setUpdatedOn(currentTime);
            authRepository.save(authEntity1);
            log.info("AuthServiceImpl::updateAuth:updated record in postgres for id: {}", id);

            // Re-index the document in Elasticsearch (filtered to whitelisted fields)
            ObjectNode jsonNode = buildDocument(authEntity, authEntity1.getStatus(),
                    authEntity1.getCreatedOn(), currentTime);
            Map<String, Object> map = objectMapper.convertValue(jsonNode, Map.class);
            esUtilService.updateDocument(Constants.AUTH_INDEX_NAME, Constants.INDEX_TYPE,
                    id, map, vergProperties.getElasticAuthJsonPath());
            log.info("AuthServiceImpl::updateAuth:updated document in elasticsearch for id: {}", id);

            // Refresh the Redis cache
            cacheService.putCache(id, jsonNode);
            log.info("AuthServiceImpl::updateAuth:refreshed cache for id: {}", id);

            map.put(Constants.AUTH_ID_RQST, id);
            response.setResult(map);
            response.setMessage(Constants.SUCCESSFULLY_UPDATED);
            response.setResponseCode(HttpStatus.OK);
            return response;

        } catch (Exception e) {
            log.error("AuthServiceImpl::updateAuth:error while updating record for id: {}", id, e);
            throw new CustomException("error while processing", e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public CustomResponse delete(String id) {
        log.info("AuthServiceImpl::delete:inside the method with id: {}", id);
        CustomResponse response = new CustomResponse();

        // Validate that the ID is not null or empty
        if (StringUtils.isEmpty(id)) {
            log.warn("AuthServiceImpl::delete:id is null or empty");
            response.setResponseCode(HttpStatus.BAD_REQUEST);
            response.setMessage(Constants.ID_NOT_FOUND);
            return response;
        }

        try {
            // Check if the entity exists in the database
            Optional<AuthEntity> entityOptional = authRepository.findById(id);
            if (entityOptional.isEmpty()) {
                log.warn("AuthServiceImpl::delete:no record found for id: {}", id);
                response.setResponseCode(HttpStatus.NOT_FOUND);
                response.setMessage(Constants.INVALID_ID);
                return response;
            }

            AuthEntity authEntity = entityOptional.get();

            // Check if the entity is already deleted
            if (Constants.DELETED.equals(authEntity.getStatus())) {
                log.warn("AuthServiceImpl::delete:record already deleted for id: {}", id);
                response.setResponseCode(HttpStatus.BAD_REQUEST);
                response.setMessage("Record is already deleted");
                return response;
            }

            // Soft delete: mark the status DELETED and set updatedOn timestamp
            authEntity.setStatus(Constants.DELETED);
            authEntity.setUpdatedOn(new Timestamp(System.currentTimeMillis()));
            authRepository.save(authEntity);
            log.info("AuthServiceImpl::delete:soft deleted record in postgres for id: {}", id);

            // Remove document from Elasticsearch
            esUtilService.deleteDocument(id, Constants.AUTH_INDEX_NAME);
            log.info("AuthServiceImpl::delete:deleted document from elasticsearch for id: {}", id);

            // Remove from Redis cache
            cacheService.deleteCache(id);
            log.info("AuthServiceImpl::delete:evicted cache for id: {}", id);

            response.setMessage(Constants.SUCCESSFULLY_DELETED);
            response.setResponseCode(HttpStatus.OK);
            auditLogService.logAudit(id, AUDIT_ENTITY_NAME, "delete", Constants.DELETED,
                    authEntity.getData(), authEntity.getData(),
                    authEntity.getCreatedOn(), authEntity.getUpdatedOn());
            return response;

        } catch (Exception e) {
            log.error("AuthServiceImpl::delete:error while deleting record for id: {}", id, e);
            throw new CustomException(Constants.ERROR, "error while deleting record",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public CustomResponse importData(MultipartFile file) {
        log.info("AuthServiceImpl::importData::started");
        return importService.processBulkImport(
                file,
                Constants.AUTH_VALIDATION_FILE_JSON,
                this::createAuth
        );
    }

    @Override
    public CustomResponse loadFromPrimaryAuth() {
        log.info("AuthServiceImpl::loadFromPrimaryAuth::started");
        return loadFromPrimaryService.loadFromPrimary(
                Constants.AUTH_INDEX_NAME,
                vergProperties.getElasticAuthJsonPath(),
                authRepository.findAll(),
                AuthEntity::getAuthId,
                e -> objectMapper.convertValue(
                        buildDocument(e.getData(), e.getStatus(), e.getCreatedOn(), e.getUpdatedOn()),
                        Map.class),
                e -> !Constants.DELETED.equals(e.getStatus()));   // skip DELETED; INACTIVE is indexed
    }

    /**
     * Builds the projection stored in Elasticsearch and Redis (and returned by read): the payload
     * plus the lifecycle status and the Postgres createdOn/updatedOn timestamps (ISO-8601). ES keeps
     * only whitelisted keys, so status/createdOn/updatedOn must be present in esAuthRequiredFields.json.
     */
    private ObjectNode buildDocument(JsonNode data, String status, Timestamp createdOn, Timestamp updatedOn) {
        ObjectNode node = objectMapper.createObjectNode();
        if (data != null && data.isObject()) {
            node.setAll((ObjectNode) data);
        }
        node.put(Constants.STATUS, status);
        if (createdOn != null) {
            node.put(Constants.CREATED_ON, createdOn.toInstant().toString());
        }
        if (updatedOn != null) {
            node.put(Constants.UPDATED_ON, updatedOn.toInstant().toString());
        }
        return node;
    }

    public void createSuccessResponse(CustomResponse response) {
        response.setParams(new RespParam());
        response.getParams().setStatus(Constants.SUCCESS);
        response.setResponseCode(HttpStatus.OK);
    }

    public String generateRedisJwtTokenKey(Object requestPayload) {
        if (requestPayload != null) {
            try {
                String reqJsonString = objectMapper.writeValueAsString(requestPayload);
                return JWT.create()
                        .withClaim(Constants.REQUEST_PAYLOAD, reqJsonString)
                        .sign(Algorithm.HMAC256(Constants.JWT_SECRET_KEY));
            } catch (JsonProcessingException e) {
                // logger.error("Error occurred while converting json object to json string", e);
            }
        }
        return "";
    }

    public void createErrorResponse(
            CustomResponse response, String errorMessage, HttpStatus httpStatus, String status) {
        response.setParams(new RespParam());
        response.getParams().setStatus(status);
        response.setResponseCode(httpStatus);
    }
}