package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Strict, read-only projection of completed trusted-fixture traces into public DTOs.
 * It never changes task state and never creates VERIFIED evidence.
 */
public final class TraceProjectionService {
    private static final int MAX_PROJECTED_TASKS = 20_000;
    private static final int MAX_PROJECTED_EVIDENCE = 100_000;
    private static final int MAX_CHUNKS = 10_000;
    private static final int MAX_EVENTS = 10_000;
    private static final int MAX_LINE_BYTES = 64 * 1024;

    private final InMemoryTraceStore traces;
    private final Map<TaskScope, Projection> projections = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.EvidenceDto> evidence = new ConcurrentHashMap<>();

    public TraceProjectionService(InMemoryTraceStore traces) {
        this.traces = Objects.requireNonNull(traces, "traces");
    }

    /**
     * Revalidates and publishes one immutable projection. Invalid traces fail closed and are not retained.
     */
    public synchronized Projection publishCompleted(TaskSnapshot snapshot) {
        Projection projection = project(snapshot);
        Projection prior = projections.get(snapshot.scope());
        int additionalEvidence = prior == null
                ? projection.evidence().size()
                : Math.max(0, projection.evidence().size() - prior.evidence().size());
        if (prior == null && projections.size() >= MAX_PROJECTED_TASKS) {
            throw new IllegalStateException("dynamic projection task limit reached");
        }
        if (evidence.size() + additionalEvidence > MAX_PROJECTED_EVIDENCE) {
            throw new IllegalStateException("dynamic projection evidence limit reached");
        }
        if (prior != null) {
            for (String id : prior.evidence().keySet()) evidence.remove(id, prior.evidence().get(id));
        }
        projections.put(snapshot.scope(), projection);
        projection.evidence().forEach(evidence::putIfAbsent);
        return projection;
    }

    public Projection project(TaskSnapshot snapshot) {
        requireEligible(snapshot);
        TraceManifest manifest = traces.manifest(snapshot.scope());
        List<TraceChunk> chunks = traces.readChunks(snapshot.scope(), MAX_CHUNKS,
                snapshot.spec().resourceBudget().maxTraceBytes());
        return project(snapshot, manifest, chunks);
    }

    /** Visible for contract tests and alternate immutable trace backends. */
    public Projection project(TaskSnapshot snapshot, TraceManifest manifest, List<TraceChunk> chunks) {
        requireEligible(snapshot);
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(chunks, "chunks");
        validateChain(snapshot, manifest, chunks);

        List<EventWithDigest> events = parseEvents(chunks, snapshot.spec().resourceBudget().maxTraceBytes());
        List<ApiDtos.PathStepDto> steps = new ArrayList<>(events.size());
        List<String> refs = new ArrayList<>(events.size());
        Map<String, ApiDtos.EvidenceDto> projectedEvidence = new LinkedHashMap<>();
        String scopeDigest = WorkerContracts.sha256((snapshot.scope().projectId() + "\n"
                + snapshot.scope().artifactDigest() + "\n" + snapshot.scope().scanId() + "\n"
                + snapshot.scope().taskId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (EventWithDigest item : events) {
            AgentJsonlTraceConverter.AgentEvent event = item.event();
            String evidenceId = "evidence-dynamic-" + scopeDigest + "-" + event.sequence();
            String kind = switch (event.eventType()) {
                case "AGENT_STARTED", "HTTP" -> "entry";
                case "CLASS_LOAD", "INSTRUMENTATION_CAPABILITY", "INSTRUMENTATION_ERROR" -> "transform";
                case "HTTP_CLIENT", "FILE", "JDBC" -> "dependency";
                case "PROCESS" -> "sink";
                default -> throw new IllegalArgumentException("unsupported Agent event type");
            };
            String symbol = event.className().isBlank() ? event.method()
                    : event.method().isBlank() ? event.className()
                    : event.className() + "#" + event.method();
            if (symbol.isBlank()) symbol = event.eventType();
            String summary = event.eventType() + " observed by veyrion-agent at " + symbol;
            String snapshotRef = "task:" + snapshot.scope().taskId()
                    + ";digest:" + item.chunkDigest() + ";sequence:" + event.sequence();
            ApiDtos.EvidenceDto evidenceDto = new ApiDtos.EvidenceDto(
                    ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                    snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                    evidenceId, event.provenanceKind(), "veyrion-agent", 0.75,
                    summary, event.timestamp(), "veyrion-agent/1",
                    "none", snapshotRef, ApiDtos.MOCK, "DYNAMIC_SUSPECTED");
            projectedEvidence.put(evidenceId, evidenceDto);
            refs.add(evidenceId);
            steps.add(new ApiDtos.PathStepDto(
                    event.eventType(), symbol, kind, "done", List.of(evidenceId),
                    "DYNAMIC_SUSPECTED", event.provenanceKind(), event.eventType(), event.sequence()));
        }
        ApiDtos.PathDto path = new ApiDtos.PathDto(
                ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                "path-dynamic-" + snapshot.scope().taskId(), snapshot.spec().targetEntryId(),
                "DYNAMIC_SUSPECTED", ApiDtos.MOCK, List.of(), "COMPLETED",
                refs, steps, snapshot.scope().taskId(), snapshot.spec().fixtureOnly(),
                snapshot.spec().requiredCapability().name(),
                snapshot.spec().requiredCapability().name() + "_COMPLETED");
        return new Projection(snapshot.scope(), path, projectedEvidence, snapshot.updatedAt().toString());
    }

    public List<ApiDtos.PathDto> pathsForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .map(Projection::path)
                .toList();
    }

    public ApiDtos.EvidenceDto evidence(String evidenceId) {
        return evidenceId == null ? null : evidence.get(evidenceId);
    }

    public List<ApiDtos.EvidenceDto> evidenceForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .flatMap(value -> value.evidence().values().stream())
                .toList();
    }

    private static void requireEligible(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        WorkerTaskSpec spec = snapshot.spec();
        boolean fixtureEligible = spec.fixtureOnly()
                && spec.requiredCapability() == WorkerCapability.FIXTURE_RUNC;
        boolean externalEligible = !spec.fixtureOnly()
                && (spec.requiredCapability() == WorkerCapability.HARDENED_GVISOR
                || spec.requiredCapability() == WorkerCapability.HARDENED_KATA);
        if (snapshot.lifecycle() != TaskLifecycle.COMPLETED
                || snapshot.stopReason() != StopReason.COMPLETED
                || !(fixtureEligible || externalEligible)) {
            throw new IllegalArgumentException(
                    "only completed fixture or hardened external tasks may be projected");
        }
    }

    private static void validateChain(TaskSnapshot snapshot, TraceManifest manifest, List<TraceChunk> chunks) {
        TaskScope scope = snapshot.scope();
        if (!scope.equals(manifest.scope())) throw new SecurityException("trace manifest scope mismatch");
        if (chunks.isEmpty() || chunks.size() != manifest.chunks().size() || chunks.size() > MAX_CHUNKS) {
            throw new IllegalArgumentException("trace manifest and chunks do not match");
        }
        long total = 0;
        String previous = null;
        for (int index = 0; index < chunks.size(); index++) {
            TraceChunk chunk = chunks.get(index);
            TraceManifest.ChunkRef ref = manifest.chunks().get(index);
            if (!scope.equals(chunk.scope())) throw new SecurityException("trace chunk scope mismatch");
            byte[] payload = chunk.payload();
            String calculated = TraceChunk.calculateDigest(chunk.schemaVersion(), chunk.scope(), chunk.sequence(),
                    chunk.previousDigest(), chunk.emittedAt(), payload);
            if (chunk.sequence() != index || ref.sequence() != index
                    || !Objects.equals(previous, chunk.previousDigest())
                    || !calculated.equals(chunk.digest())
                    || !chunk.digest().equals(ref.digest())
                    || payload.length != ref.payloadBytes()
                    || !chunk.emittedAt().equals(ref.emittedAt())) {
                throw new SecurityException("trace chain validation failed");
            }
            if (payload.length > snapshot.spec().resourceBudget().maxTraceBytes() - total) {
                throw new IllegalArgumentException("trace exceeds task byte budget");
            }
            total += payload.length;
            previous = chunk.digest();
        }
        if (total != manifest.totalPayloadBytes()
                || total > snapshot.spec().resourceBudget().maxTraceBytes()
                || !Objects.equals(previous, manifest.headDigest())) {
            throw new SecurityException("trace manifest summary mismatch");
        }
    }

    private static List<EventWithDigest> parseEvents(List<TraceChunk> chunks, long maxBytes) {
        List<EventWithDigest> result = new ArrayList<>();
        long bytes = 0;
        long expectedSequence = 0;
        for (TraceChunk chunk : chunks) {
            byte[] payload = chunk.payload();
            if (payload.length == 0 || payload[payload.length - 1] != '\n') {
                throw new IllegalArgumentException("trace chunk must contain complete JSONL lines");
            }
            if (payload.length > maxBytes - bytes) throw new IllegalArgumentException("trace exceeds byte budget");
            bytes += payload.length;
            int start = 0;
            for (int index = 0; index < payload.length; index++) {
                if (payload[index] != '\n') continue;
                int length = index - start;
                if (length <= 0 || length > MAX_LINE_BYTES) {
                    throw new IllegalArgumentException("trace contains an invalid JSONL line length");
                }
                if (result.size() >= MAX_EVENTS) throw new IllegalArgumentException("trace exceeds event limit");
                byte[] line = Arrays.copyOfRange(payload, start, index);
                AgentJsonlTraceConverter.AgentEvent event =
                        AgentJsonlTraceConverter.parseAcceptedLine(line, line.length, expectedSequence);
                expectedSequence = Math.addExact(event.sequence(), 1);
                result.add(new EventWithDigest(event, chunk.digest()));
                start = index + 1;
            }
        }
        if (result.isEmpty()) throw new IllegalArgumentException("trace contains no events");
        return List.copyOf(result);
    }

    private record EventWithDigest(AgentJsonlTraceConverter.AgentEvent event, String chunkDigest) { }

    public record Projection(TaskScope scope, ApiDtos.PathDto path,
                             Map<String, ApiDtos.EvidenceDto> evidence, String completedAt) {
        public Projection {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(path, "path");
            evidence = Map.copyOf(evidence);
            Objects.requireNonNull(completedAt, "completedAt");
        }
    }
}
