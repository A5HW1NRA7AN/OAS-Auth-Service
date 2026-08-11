package com.catalogue.verg.core.util;

import java.util.Arrays;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
public class VergProperties {

        @Value("${spring.redis.cacheTtl}")
        private long searchResultRedisTtl;

        @Value("${search.string.max.regex.length}")
        private int searchStringMaxRegexLength;
        @Value("${elastic.required.field.audit.json.path}")
        private String elasticAuditJsonPath;
    
        @Value("${elastic.required.field.auth.json.path}")
        private String elasticAuthJsonPath;
    }
