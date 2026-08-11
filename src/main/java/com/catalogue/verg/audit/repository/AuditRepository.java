package com.catalogue.verg.audit.repository;

import com.catalogue.verg.audit.entity.AuditEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditRepository extends JpaRepository<AuditEntity, String> {

}