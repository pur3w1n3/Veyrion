package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.List;

/**
 * 只读 SecurityHypothesis 查询（P1-08）。未知 family 仍以 UNKNOWN 可读。
 */
public interface HypothesisQueryPort {
    List<SecurityHypothesis> hypotheses(String scanId);
}
