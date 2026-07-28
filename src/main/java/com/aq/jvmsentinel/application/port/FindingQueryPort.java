package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Read-only finding query (P1-08). HTTP adapters project to legacy {@code /api/v1} maps.
 * Does not elevate verification status.
 */
public interface FindingQueryPort {
    boolean scanExists(String scanId);

    /** Neutral finding view maps for a scan; empty when the scan is missing. */
    Optional<List<Map<String, Object>>> findingsForScan(String scanId);

    Optional<Map<String, Object>> findingView(String findingId);
}
