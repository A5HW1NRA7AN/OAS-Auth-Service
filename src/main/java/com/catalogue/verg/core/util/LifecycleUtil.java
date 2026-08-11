package com.catalogue.verg.core.util;

import java.util.Set;

/**
 * Central definition of the editorial-lifecycle state machine, kept in one place so the same
 * rules can be reused when the lifecycle is rolled out to the other registry entities.
 *
 * <p>Statuses live on the entity's {@code status} column. {@code ACTIVE} = published/live
 * (only {@code review} can set it), {@code INACTIVE} = deactivated (set by the toggle endpoint),
 * {@code DELETED} = soft-deleted (set by {@code delete}).
 */
public final class LifecycleUtil {

    private LifecycleUtil() {
    }

    /** Statuses from which {@code add PUT /add/{id}} may (re-)submit a record to PENDING. */
    public static final Set<String> ADD_PROMOTABLE = Set.of(Constants.DRAFT, Constants.REWORK);

    /** {@code approve} acts on a PENDING record. */
    public static final String APPROVE_FROM = Constants.PENDING;
    public static final Set<String> APPROVE_TARGETS =
            Set.of(Constants.APPROVED, Constants.REJECTED, Constants.REWORK);

    /** {@code review} acts on an APPROVED record. */
    public static final String REVIEW_FROM = Constants.APPROVED;
    public static final Set<String> REVIEW_TARGETS =
            Set.of(Constants.ACTIVE, Constants.REJECTED, Constants.REWORK);

    /**
     * Normalises a requested target status: {@code PUBLISHED} is accepted as a friendly alias for
     * the terminal live state {@code ACTIVE}. All other values are returned untouched (null-safe).
     */
    public static String normalizeTarget(String status) {
        if (status == null) {
            return null;
        }
        String upper = status.trim().toUpperCase();
        return Constants.PUBLISHED.equals(upper) ? Constants.ACTIVE : upper;
    }
}
