package com.aq.jvmsentinel.domain.analyzer;

import java.util.Objects;

/** Fail-closed Analyzer ingress rejection. */
public final class AnalyzerRejectException extends RuntimeException {
    private final AnalyzerRejectReason reason;

    public AnalyzerRejectException(AnalyzerRejectReason reason, String message) {
        super(message);
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    public AnalyzerRejectReason reason() {
        return reason;
    }
}
