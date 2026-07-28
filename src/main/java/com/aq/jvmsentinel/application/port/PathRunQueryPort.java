package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Read-only PathRun query (P1-08). Merges persisted and projected runs for a scan.
 * MOCK provenance stays visible; callers must not upgrade verification status.
 */
public interface PathRunQueryPort {
    boolean scanExists(String scanId);

    /** Neutral PathRun view maps; empty when the scan is missing. */
    Optional<List<Map<String, Object>>> pathRunsForScan(String scanId);
}
