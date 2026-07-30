package com.aq.jvmsentinel.domain.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 进程内 Fake evidence store，用于 Test Analyzer / contract 证明。
 * 非 Control Plane SQLite adapter — Analyzer 永不得接收 DB handle。
 */
public final class InMemoryAnalyzerEvidenceStore implements AnalyzerEvidenceStore {
    private final ConcurrentMap<String, PublishedEvidence> bySubmission = new ConcurrentHashMap<>();

    @Override
    public void publishAtomically(PublishedEvidence evidence) {
        PublishedEvidence prior = bySubmission.putIfAbsent(evidence.submissionId(), evidence);
        if (prior != null) {
            if (!prior.fingerprint().equals(evidence.fingerprint())) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.IDEMPOTENCY_CONFLICT,
                        "submissionId payload conflict");
            }
            return;
        }
    }

    @Override
    public Optional<PublishedEvidence> findBySubmissionId(String submissionId) {
        return Optional.ofNullable(bySubmission.get(submissionId));
    }

    @Override
    public List<PublishedEvidence> findByScanId(String scanId) {
        List<PublishedEvidence> matches = new ArrayList<>();
        for (PublishedEvidence evidence : bySubmission.values()) {
            if (evidence.scope().scanId().equals(scanId)) {
                matches.add(evidence);
            }
        }
        return List.copyOf(matches);
    }

    public int size() {
        return bySubmission.size();
    }
}
