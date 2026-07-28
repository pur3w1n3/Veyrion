package com.aq.jvmsentinel.application.port;

import java.util.Map;
import java.util.Optional;

/**
 * Read-only scan summary query (P1-08). HTTP adapters project to legacy {@code /api/v1} maps.
 */
public interface ScanQueryPort {
    boolean exists(String scanId);

    /** Neutral scan view map; empty when the scan is missing. */
    Optional<Map<String, Object>> scanView(String scanId);
}
