package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;

/**
 * Read-only AI provider inventory query (P1-08 incremental port split).
 * Does not expose raw credentials; maps are wire-safe projections.
 */
public interface ProviderQueryPort {
    /** Neutral provider view maps (never include apiKey / secret material). */
    List<Map<String, Object>> listProviders();
}
