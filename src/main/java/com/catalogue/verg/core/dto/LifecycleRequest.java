package com.catalogue.verg.core.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for the lifecycle status-transition endpoints (approve / review).
 * Carries the target record id and the requested target status.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LifecycleRequest {
    private String id;
    private String status;
}
