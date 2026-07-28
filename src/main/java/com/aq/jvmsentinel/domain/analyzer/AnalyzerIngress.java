package com.aq.jvmsentinel.domain.analyzer;

import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.universe.CoverageGap;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Control-plane Analyzer ingress: bounded staging → full validation → atomic evidence publish.
 *
 * <p>Designed for out-of-process Analyzers; same-process Test Analyzer proves the contract.
 * Partial / rejected submissions never enter the authoritative evidence store.
 */
public final class AnalyzerIngress {
    private final AnalyzerEvidenceStore store;
    private final Clock clock;
    private final ConcurrentMap<String, Session> sessions = new ConcurrentHashMap<>();

    public AnalyzerIngress(AnalyzerEvidenceStore store) {
        this(store, Clock.systemUTC());
    }

    public AnalyzerIngress(AnalyzerEvidenceStore store, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public String openSession(AnalyzerSessionSpec spec) {
        Objects.requireNonNull(spec, "spec");
        String sessionId = "asess-" + UUID.randomUUID();
        sessions.put(sessionId, new Session(spec));
        return sessionId;
    }

    public void cancel(String sessionId) {
        Session session = requireSession(sessionId);
        session.cancelled = true;
        session.staged.clear();
    }

    public void stageChunk(String sessionId, IrChunk chunk) {
        Session session = requireSession(sessionId);
        ensureOpen(session);
        Objects.requireNonNull(chunk, "chunk");
        if (!session.spec.schemaRange().accepts(chunk.schemaVersion())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCHEMA_INCOMPATIBLE,
                    "chunk schemaVersion outside accepted range");
        }
        if (!session.spec.scope().equals(chunk.scope())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCOPE_MISMATCH,
                    "chunk scope mismatch");
        }
        if (chunk.payloadBytes() > session.spec.budget().maxChunkBytes()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                    "chunk exceeds session maxChunkBytes");
        }
        if (session.staged.size() >= session.spec.budget().maxChunks()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                    "chunk count exceeds session maxChunks");
        }
        long nextTotal = session.totalBytes() + chunk.payloadBytes();
        if (nextTotal > session.spec.budget().maxTotalBytes()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                    "total payload exceeds session maxTotalBytes");
        }
        if (session.staged.containsKey(chunk.sequence())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.DUPLICATE_CHUNK,
                    "duplicate chunk sequence " + chunk.sequence());
        }
        long expected = session.staged.size();
        if (chunk.sequence() != expected) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                    "chunk sequence must be contiguous; expected " + expected);
        }
        session.staged.put(chunk.sequence(), chunk);
    }

    public CommitResult commit(String sessionId, AnalyzerSubmission submission) {
        Session session = requireSession(sessionId);
        Objects.requireNonNull(submission, "submission");

        // Scope/deadline authorization must precede idempotency replay. A submission id
        // is globally indexed, so a valid session from another scan must not receive it.
        ensureOpen(session);
        if (!session.spec.scope().equals(submission.scope())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCOPE_MISMATCH,
                    "submission scope does not match session");
        }
        if (!session.spec.artifactDigest().equals(submission.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "submission artifactDigest does not match session");
        }
        if (!session.spec.policyDigest().equals(submission.policyDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.POLICY_DIGEST_MISMATCH,
                    "submission policyDigest does not match session");
        }
        var prior = store.findBySubmissionId(submission.submissionId());
        if (prior.isPresent()) {
            if (!session.spec.scope().equals(prior.get().scope())
                    || !session.spec.artifactDigest().equals(prior.get().scope().artifactDigest())) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.SCOPE_MISMATCH,
                        "idempotency replay scope mismatch");
            }
            if (!prior.get().fingerprint().equals(submission.fingerprint())) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.IDEMPOTENCY_CONFLICT,
                        "replay fingerprint conflict");
            }
            return CommitResult.idempotent(prior.get());
        }

        validateSubmission(session, submission);

        List<IrChunk> ordered = orderedChunks(session);
        validateManifestAgainstStaging(submission.chunkManifest(), ordered);

        if (submission.terminalState() != AnalyzerTerminalState.SUCCESS) {
            session.closed = true;
            session.staged.clear();
            return CommitResult.rejectedTerminal(submission.terminalState(), submission.stopReason());
        }

        List<IrNode> nodes = projectNodes(ordered, session.spec.budget().maxNodes());
        List<CoverageGap> gaps = submission.coverageGaps().stream()
                .map(AnalyzerCoverageGapDto::toDomain)
                .toList();

        AnalyzerEvidenceStore.PublishedEvidence published = new AnalyzerEvidenceStore.PublishedEvidence(
                submission.submissionId(),
                submission.scope(),
                submission.fingerprint(),
                submission.terminalState(),
                nodes,
                gaps,
                submission.diagnostics(),
                submission.resourceUsage(),
                submission.stopReason());
        store.publishAtomically(published);
        session.closed = true;
        session.staged.clear();
        return CommitResult.published(published);
    }

    private void validateSubmission(Session session, AnalyzerSubmission submission) {
        if (!session.spec.schemaRange().accepts(submission.schemaVersion())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCHEMA_INCOMPATIBLE,
                    "submission schemaVersion outside accepted range");
        }
        if (!session.spec.scope().equals(submission.scope())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCOPE_MISMATCH,
                    "submission scope mismatch");
        }
        if (!session.spec.artifactDigest().equals(submission.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "artifact digest mismatch");
        }
        if (!session.spec.policyDigest().equals(submission.policyDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.POLICY_DIGEST_MISMATCH,
                    "policy digest mismatch");
        }
        if (!session.spec.acceptedCapabilities().equals(submission.acceptedCapabilities())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.UNKNOWN_CAPABILITY,
                    "acceptedCapabilities do not match negotiated set");
        }
        AnalyzerBudget budget = session.spec.budget();
        AnalyzerResourceUsage usage = submission.resourceUsage();
        if (usage.chunkCount() > budget.maxChunks()
                || usage.totalPayloadBytes() > budget.maxTotalBytes()
                || usage.nodeCount() > budget.maxNodes()
                || usage.wallClockMillis() > budget.maxWallClockMillis()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                    "resource usage exceeds session budget");
        }
        if (usage.chunkCount() != session.staged.size()
                || usage.totalPayloadBytes() != session.totalBytes()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                    "resourceUsage does not match staged chunks");
        }
    }

    private void validateManifestAgainstStaging(IrChunkManifest manifest, List<IrChunk> ordered) {
        if (manifest.chunks().size() > ordered.size()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.MISSING_CHUNK,
                    "manifest references chunks not staged");
        }
        if (manifest.chunks().size() < ordered.size()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                    "staged chunks not fully declared in manifest");
        }
        for (int i = 0; i < ordered.size(); i++) {
            IrChunk chunk = ordered.get(i);
            IrChunkManifest.ChunkRef ref = manifest.chunks().get(i);
            if (ref.sequence() != chunk.sequence()
                    || !ref.kind().equals(chunk.kind())
                    || !ref.payloadDigest().equals(chunk.payloadDigest())
                    || ref.payloadBytes() != chunk.payloadBytes()) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                        "manifest entry mismatch at sequence " + i);
            }
        }
        // Explicit missing-chunk probe: gaps in staged sequences already prevented at stage time;
        // commit with fewer manifest entries than required contiguous 0..n-1 is MISSING_CHUNK.
        for (int expected = 0; expected < ordered.size(); expected++) {
            final long seq = expected;
            boolean present = ordered.stream().anyMatch(chunk -> chunk.sequence() == seq);
            if (!present) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.MISSING_CHUNK,
                        "missing chunk sequence " + expected);
            }
        }
    }

    private List<IrChunk> orderedChunks(Session session) {
        List<IrChunk> ordered = new ArrayList<>(session.staged.size());
        for (long sequence = 0; sequence < session.staged.size(); sequence++) {
            IrChunk chunk = session.staged.get(sequence);
            if (chunk == null) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.MISSING_CHUNK,
                        "missing chunk sequence " + sequence);
            }
            ordered.add(chunk);
        }
        return ordered;
    }

    private List<IrNode> projectNodes(List<IrChunk> chunks, int maxNodes) {
        List<IrNode> nodes = new ArrayList<>();
        for (IrChunk chunk : chunks) {
            if (nodes.size() >= maxNodes) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                        "projected nodes exceed maxNodes");
            }
            switch (chunk.kind()) {
                case IrChunk.KIND_PROGRAM_NODE -> nodes.add(toProgramNode(chunk.payload()));
                case IrChunk.KIND_ENTRY -> nodes.add(toEntryNode(chunk.payload()));
                case IrChunk.KIND_COVERAGE_GAP -> {
                    // Gaps are published from submission.coverageGaps, not as IR nodes.
                }
                default -> {
                    // Unknown kinds are retained only as diagnostics via payload; never elevate status.
                }
            }
        }
        return List.copyOf(nodes);
    }

    private static ProgramNode toProgramNode(Map<String, Object> payload) {
        String elementKind = string(payload, "elementKind", "CLASS");
        String language = string(payload, "language", "UNKNOWN");
        String symbol = string(payload, "symbol", "");
        String location = string(payload, "location", "");
        String id = string(payload, "id", StableNodeIds.programClass(symbol.isBlank() ? "unknown" : symbol));
        String provenance = string(payload, "provenanceKind", "FACT");
        List<String> evidenceRefs = stringList(payload.get("evidenceRefs"));
        Map<String, Object> extensions = namespacedExtensions(payload.get("extensions"));
        return new ProgramNode(id, elementKind, language, symbol, location,
                evidenceRefs, provenance, extensions);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> namespacedExtensions(Object raw) {
        if (!(raw instanceof Map<?, ?> map) || map.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String key = String.valueOf(entry.getKey()).trim();
            if (key.isEmpty()) {
                continue;
            }
            out.put(key, entry.getValue());
        }
        return out;
    }

    private static List<String> stringList(Object raw) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item == null) {
                continue;
            }
            String text = String.valueOf(item).trim();
            if (!text.isEmpty()) {
                out.add(text);
            }
        }
        return out;
    }

    private static EntryNode toEntryNode(Map<String, Object> payload) {
        String protocol = string(payload, "protocol", "UNKNOWN");
        String operation = string(payload, "operation", "");
        String address = string(payload, "address", "");
        String declaring = string(payload, "declaringSymbol", "");
        String id = string(payload, "id", StableNodeIds.entry(address.isBlank() ? "unknown" : address));
        return new EntryNode(id, protocol, operation, address, declaring,
                List.of(), List.of(), "FACT", "STATIC_INFERRED");
    }

    private static String string(Map<String, Object> payload, String key, String defaultValue) {
        Object value = payload.get(key);
        if (value == null) {
            return defaultValue;
        }
        String text = String.valueOf(value);
        return text.isBlank() ? defaultValue : text;
    }

    private Session requireSession(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session == null) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SESSION_LATE,
                    "unknown or expired session");
        }
        return session;
    }

    private void ensureOpen(Session session) {
        if (session.cancelled) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SESSION_CANCELLED,
                    "analyzer session cancelled");
        }
        if (session.closed) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SESSION_LATE,
                    "analyzer session already closed");
        }
        Instant now = clock.instant();
        if (now.isAfter(session.spec.deadline())) {
            session.closed = true;
            session.staged.clear();
            throw new AnalyzerRejectException(AnalyzerRejectReason.SESSION_LATE,
                    "analyzer session past deadline");
        }
    }

    /** Negotiate offered capabilities against the server allowlist (fail-closed). */
    public Set<AnalyzerCapability> negotiate(
            CapabilityNegotiation offer,
            Set<AnalyzerCapability> serverAllowed
    ) {
        Objects.requireNonNull(offer, "offer");
        if (!offer.schemaRange().accepts(AnalyzerContracts.SCHEMA_VERSION)) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.SCHEMA_INCOMPATIBLE,
                    "analyzer schema range incompatible");
        }
        return offer.accept(serverAllowed);
    }

    public record CommitResult(
            boolean published,
            boolean idempotentReplay,
            AnalyzerTerminalState terminalState,
            String stopReason,
            AnalyzerEvidenceStore.PublishedEvidence evidence
    ) {
        static CommitResult published(AnalyzerEvidenceStore.PublishedEvidence evidence) {
            return new CommitResult(true, false, evidence.terminalState(), evidence.stopReason(), evidence);
        }

        static CommitResult idempotent(AnalyzerEvidenceStore.PublishedEvidence evidence) {
            return new CommitResult(true, true, evidence.terminalState(), evidence.stopReason(), evidence);
        }

        static CommitResult rejectedTerminal(AnalyzerTerminalState state, String stopReason) {
            return new CommitResult(false, false, state, stopReason, null);
        }
    }

    private static final class Session {
        private final AnalyzerSessionSpec spec;
        private final Map<Long, IrChunk> staged = new LinkedHashMap<>();
        private volatile boolean cancelled;
        private volatile boolean closed;

        private Session(AnalyzerSessionSpec spec) {
            this.spec = spec;
        }

        private long totalBytes() {
            long total = 0;
            for (IrChunk chunk : staged.values()) {
                total += chunk.payloadBytes();
            }
            return total;
        }
    }
}
