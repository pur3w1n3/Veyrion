package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.List;

/**
 * Read-only SecurityHypothesis query (P1-08). Unknown family stays readable as UNKNOWN.
 */
public interface HypothesisQueryPort {
    List<SecurityHypothesis> hypotheses(String scanId);
}
