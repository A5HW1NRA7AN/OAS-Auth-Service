package com.catalogue.verg.core.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.ValidationMessage;
import java.io.InputStream;
import java.util.Set;

import com.catalogue.verg.core.exception.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PayloadValidation {

    private Logger logger = LoggerFactory.getLogger(PayloadValidation.class);

    @Autowired
    private ObjectMapper objectMapper;

    public void validatePayload(String fileName, JsonNode payload) {
//    log.info("PayloadValidation::validatePayload:inside");
        try {
            JsonSchemaFactory schemaFactory = JsonSchemaFactory.getInstance();
            InputStream schemaStream = schemaFactory.getClass().getResourceAsStream(fileName);
            JsonSchema schema = schemaFactory.getSchema(schemaStream);
            validateAgainstSchema(schema, payload);
        } catch (Exception e) {
            logger.error("Failed to validate payload", e);
            throw new CustomException("Failed to validate payload", e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Validates a payload against the entity schema but with the top-level {@code required} array
     * removed, so incomplete records are accepted (used by the {@code draft} endpoint). Type and
     * structural constraints are still enforced.
     */
    public void validatePayloadRelaxed(String fileName, JsonNode payload) {
        try {
            JsonSchemaFactory schemaFactory = JsonSchemaFactory.getInstance();
            InputStream schemaStream = schemaFactory.getClass().getResourceAsStream(fileName);
            JsonNode schemaNode = objectMapper.readTree(schemaStream);
            if (schemaNode instanceof ObjectNode) {
                ((ObjectNode) schemaNode).remove("required");
            }
            JsonSchema schema = schemaFactory.getSchema(schemaNode);
            validateAgainstSchema(schema, payload);
        } catch (Exception e) {
            logger.error("Failed to validate payload", e);
            throw new CustomException("Failed to validate payload", e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    private void validateAgainstSchema(JsonSchema schema, JsonNode payload) {
        if (payload.isArray()) {
            for (JsonNode objectNode : payload) {
                validateObject(schema, objectNode);
            }
        } else {
            validateObject(schema, payload);
        }
    }

    private void validateObject(JsonSchema schema, JsonNode objectNode) {
        Set<ValidationMessage> validationMessages = schema.validate(objectNode);
        if (!validationMessages.isEmpty()) {
            StringBuilder errorMessage = new StringBuilder("Validation error(s): \n");
            for (ValidationMessage message : validationMessages) {
                errorMessage.append(message.getMessage()).append("\n");
            }
            logger.error("Validation Error", errorMessage.toString());
            throw new CustomException("Validation Error", errorMessage.toString(), HttpStatus.BAD_REQUEST);
        }
    }
}
