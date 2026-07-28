package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;

import java.util.Optional;

/**
 * Read-only Coverage Matrix query (P1-08). SUCCESS is never mapped to safe/secure.
 */
public interface CoverageQueryPort {
    Optional<CoverageMatrix> coverage(String scanId);
}
