package com.catalogue.verg.auth.repository;

import com.catalogue.verg.auth.entity.AuthEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthRepository extends JpaRepository<AuthEntity, String> {

}