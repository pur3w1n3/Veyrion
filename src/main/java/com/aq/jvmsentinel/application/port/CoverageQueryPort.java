package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;

import java.util.Optional;

/**
 * 只读 Coverage Matrix 查询（P1-08）。SUCCESS 永不等同于 safe/secure。
 */
public interface CoverageQueryPort {
    Optional<CoverageMatrix> coverage(String scanId);
}
