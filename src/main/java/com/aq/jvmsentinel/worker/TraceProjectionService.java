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
 * Strict, read-only projection of completed authorized artifact traces into public DTOs.
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
        Map<String, List<ApiDtos.PathStepDto>> routeSteps = new LinkedHashMap<>();
        Map<String, List<String>> routeRefs = new LinkedHashMap<>();
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
            String route = event.detail().getOrDefault("route", "");
            String httpMethod = event.detail().getOrDefault("httpMethod", "");
            String summary = event.eventType() + " observed by veyrion-agent at " + symbol;
            String stepDetail = event.eventType() + " observed by veyrion-agent at " + symbol;
            if ("HTTP".equals(event.eventType()) && !route.isBlank()) {
                HttpObservation observation = httpObservation(event.detail(), route, httpMethod);
                summary = "HTTP probe observed " + observation.method() + " "
                        + observation.route() + " (target " + observation.requestTarget() + ") -> "
                        + observation.response() + " at " + symbol;
                stepDetail = summary;
            }
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
            ApiDtos.PathStepDto step = new ApiDtos.PathStepDto(
                    event.eventType(), stepDetail, kind, "done", List.of(evidenceId),
                    "DYNAMIC_SUSPECTED", event.provenanceKind(), event.eventType(), event.sequence());
            steps.add(step);
            if ("HTTP".equals(event.eventType()) && !route.isBlank()) {
                String routeKey = (httpMethod.isBlank() ? "GET" : httpMethod) + " " + route;
                routeSteps.computeIfAbsent(routeKey, ignored -> new ArrayList<>()).add(step);
                routeRefs.computeIfAbsent(routeKey, ignored -> new ArrayList<>()).add(evidenceId);
            }
        }
        ApiDtos.PathDto path = new ApiDtos.PathDto(
                ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                "path-dynamic-" + snapshot.scope().taskId(), snapshot.spec().targetEntryId(),
                "DYNAMIC_SUSPECTED", ApiDtos.MOCK, List.of(), "COMPLETED",
                refs, steps, snapshot.scope().taskId(), false,
                snapshot.spec().requiredCapability().name(),
                snapshot.spec().requiredCapability().name() + "_COMPLETED");
        List<ApiDtos.PathDto> paths = new ArrayList<>();
        paths.add(path);
        int routeIndex = 0;
        for (Map.Entry<String, List<ApiDtos.PathStepDto>> entry : routeSteps.entrySet()) {
            String routeKey = entry.getKey();
            String pathId = "path-dynamic-" + snapshot.scope().taskId() + "-route-" + routeIndex++;
            paths.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                    snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                    pathId, snapshot.spec().targetEntryId(),
                    "DYNAMIC_SUSPECTED", ApiDtos.MOCK, List.of(routeKey), "COMPLETED",
                    List.copyOf(routeRefs.getOrDefault(routeKey, List.of())),
                    List.copyOf(entry.getValue()), snapshot.scope().taskId(), false,
                    snapshot.spec().requiredCapability().name(),
                    snapshot.spec().requiredCapability().name() + "_COMPLETED"));
        }
        return new Projection(snapshot.scope(), path, List.copyOf(paths), projectedEvidence,
                snapshot.updatedAt().toString());
    }

    public List<ApiDtos.PathDto> pathsForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .flatMap(value -> value.paths().stream())
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
        boolean externalEligible = spec.authorized()
                && (spec.requiredCapability() == WorkerCapability.TRUSTED_DOCKER
                || spec.requiredCapability() == WorkerCapability.HARDENED_GVISOR
                || spec.requiredCapability() == WorkerCapability.HARDENED_KATA);
        if (snapshot.lifecycle() != TaskLifecycle.COMPLETED
                || snapshot.stopReason() != StopReason.COMPLETED
                || !externalEligible) {
            throw new IllegalArgumentException(
                    "only completed authorized artifact tasks may be projected");
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

    /**
     * Builds a bounded public view of a loopback probe. Query values are never exposed: only
     * parameter names and value lengths cross the evidence boundary.
     */
    private static HttpObservation httpObservation(Map<String, String> detail, String route,
                                                   String method) {
        String safeRoute = safeRoute(route);
        String rawTarget = detail.getOrDefault("requestTarget", route);
        String safeTarget = safeRequestTarget(rawTarget, safeRoute);
        String safeMethod = safeMethod(method);
        String status = detail.getOrDefault("status", "UNKNOWN");
        String safeStatus = status.matches("[1-5][0-9]{2}") ? "HTTP " + status : "HTTP UNKNOWN";
        String error = detail.getOrDefault("error", "");
        if (!error.isBlank()) {
            String safeError = error.matches("[A-Za-z0-9_.$-]{1,64}") ? error : "ProbeError";
            safeStatus += " (" + safeError + ")";
        }
        return new HttpObservation(safeMethod, safeRoute, safeTarget, safeStatus);
    }

    private static String safeMethod(String method) {
        return method != null && method.matches("(?i)GET|POST|PUT|PATCH|DELETE")
                ? method.toUpperCase(java.util.Locale.ROOT) : "HTTP";
    }

    private static String safeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String value = route.length() > 512 ? route.substring(0, 512) : route;
        return value.matches("/[A-Za-z0-9_./{}:-]{0,511}") ? value : "/<redacted-route>";
    }

    private static String safeRequestTarget(String target, String fallbackRoute) {
        if (target == null || target.isBlank()) return fallbackRoute;
        String value = target.length() > 512 ? target.substring(0, 512) : target;
        int queryIndex = value.indexOf('?');
        String targetRoute = queryIndex < 0 ? value : value.substring(0, queryIndex);
        String safeTargetRoute = safeRoute(targetRoute);
        if (queryIndex < 0 || queryIndex == value.length() - 1) return safeTargetRoute;
        String query = value.substring(queryIndex + 1);
        StringBuilder redacted = new StringBuilder(safeTargetRoute).append('?');
        String[] pairs = query.split("&", -1);
        int emitted = 0;
        for (String pair : pairs) {
            if (pair.isBlank() || emitted >= 32) continue;
            int equals = pair.indexOf('=');
            String name = equals < 0 ? pair : pair.substring(0, equals);
            String rawValue = equals < 0 ? "" : pair.substring(equals + 1);
            if (!name.matches("[A-Za-z0-9_:-]{1,64}")) name = "param" + emitted;
            if (emitted > 0) redacted.append('&');
            redacted.append(name).append("=<redacted:length=")
                    .append(Math.min(rawValue.length(), 256)).append('>');
            emitted++;
        }
        return redacted.toString();
    }

    private record HttpObservation(String method, String route, String requestTarget, String response) { }

    public record Projection(TaskScope scope, ApiDtos.PathDto path, List<ApiDtos.PathDto> paths,
                             Map<String, ApiDtos.EvidenceDto> evidence, String completedAt) {
        public Projection {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(path, "path");
            paths = List.copyOf(paths == null || paths.isEmpty() ? List.of(path) : paths);
            evidence = Map.copyOf(evidence);
            Objects.requireNonNull(completedAt, "completedAt");
        }
    }
}
