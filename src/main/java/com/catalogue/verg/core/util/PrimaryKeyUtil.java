package com.catalogue.verg.core.util;

import com.datastax.oss.driver.api.core.uuid.Uuids;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class PrimaryKeyUtil {

    public static final int DEFAULT_KEY_LENGTH = 12;

    private final ObjectMapper objectMapper;

    public String generateKey(String fileName) {
        log.info("PrimaryKeyUtil::generateKey::reading schema: {}", fileName);
        JsonNode primaryKeyProperty = extractPrimaryKeyProperty(fileName);
        String prefix = extractPrefix(primaryKeyProperty);
        int keyLength = extractKeyLength(primaryKeyProperty);
        return buildKey(prefix, keyLength);
    }

//    public String generateKey(String fileName, int keyLength) {
//        log.info("PrimaryKeyUtil::generateKey::reading schema: {}", fileName);
//        JsonNode primaryKeyProperty = extractPrimaryKeyProperty(fileName);
//        String prefix = extractPrefix(primaryKeyProperty);
//        return buildKey(prefix, keyLength);
//    }

    private String buildKey(String prefix, int keyLength) {
        UUID idUuid = Uuids.timeBased();

        if (prefix != null) {
            String key = prefix + generateRandomDigits(keyLength);
            log.info("PrimaryKeyUtil::generateKey::generated prefix+random key: {}+{} (length {})", prefix, key, keyLength);
            return key;
        } else {
            log.info("PrimaryKeyUtil::generateKey::no prefix found, falling back to UUID");
            return String.valueOf(idUuid);
        }
    }

    private JsonNode extractPrimaryKeyProperty(String fileName) {
        try {
            InputStream schemaStream = getClass().getResourceAsStream(fileName);
            if (schemaStream == null) {
                log.warn("PrimaryKeyUtil::extractPrimaryKeyProperty::schema file not found: {}", fileName);
                return null;
            }
            JsonNode schemaNode = objectMapper.readTree(schemaStream);
            JsonNode properties = schemaNode.get("properties");

            if (properties != null) {
                for (JsonNode property : properties) {
                    // Look for any property that has BOTH "prefix" and "key" attributes
                    if (property.has("prefix") && property.has("key") && property.get("key").asText().equalsIgnoreCase("primary")) {
                        return property;
                    }
                }
            }
        } catch (Exception e) {
            log.error("PrimaryKeyUtil::extractPrimaryKeyProperty::error parsing schema file", e);
        }
        return null;
    }

    private String extractPrefix(JsonNode primaryKeyProperty) {
        if (primaryKeyProperty == null) {
            return null;
        }
        String prefix = primaryKeyProperty.get("prefix").asText();
        log.debug("PrimaryKeyUtil::extractPrefix::found prefix: {}", prefix);
        return prefix;
    }

    private int extractKeyLength(JsonNode primaryKeyProperty) {
        if (primaryKeyProperty != null && primaryKeyProperty.has("keyLength")) {
            int keyLength = primaryKeyProperty.get("keyLength").asInt();
            if (keyLength > 0) {
                log.debug("PrimaryKeyUtil::extractKeyLength::found keyLength: {}", keyLength);
                return keyLength;
            }
            log.warn("PrimaryKeyUtil::extractKeyLength::invalid keyLength {}, falling back to default {}", keyLength, DEFAULT_KEY_LENGTH);
        }
        return DEFAULT_KEY_LENGTH;
    }

    private String generateRandomDigits(int count) {
        SecureRandom random = new SecureRandom();
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < count; i++) {
            digits.append(random.nextInt(10));
        }
        return digits.toString();
    }


}
