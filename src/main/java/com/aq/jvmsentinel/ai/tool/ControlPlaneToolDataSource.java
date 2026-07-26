package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Read-only projection of an already persisted scan. Default path never executes
 * artifacts; {@link #queryCode} may perform a bounded ZIP string/config scan of
 * the already-registered artifact (same trust boundary as synthetic identity harvest).
 */
public final class ControlPlaneToolDataSource implements ToolDataSource {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_SQL_EVENTS_IN_FACT = 8;
    private static final int MAX_SQL_TEXT = 240;

    private final ControlPlaneStore store;
    private final String scanId;
    private final DynamicEvidenceSource dynamicEvidenceSource;
    private final DynamicProbeExecutor dynamicProbeExecutor;
    private final PathRunSource pathRunSource;
    private final ExperimentPlanAcceptor experimentPlanAcceptor;

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId) {
        this(store, scanId, (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource) {
        this(store, scanId, dynamicEvidenceSource, (scopedScanId, scope, principalId, jobId, entrypointRef,
                candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader)
                -> Optional.empty());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor,
                (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor, pathRunSource,
                (scopedScanId, plan) -> { });
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource,
                                      ExperimentPlanAcceptor experimentPlanAcceptor) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.dynamicEvidenceSource = Objects.requireNonNull(dynamicEvidenceSource, "dynamicEvidenceSource");
        this.dynamicProbeExecutor = Objects.requireNonNull(dynamicProbeExecutor, "dynamicProbeExecutor");
        this.pathRunSource = Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.experimentPlanAcceptor = Objects.requireNonNull(experimentPlanAcceptor, "experimentPlanAcceptor");
    }

    @Override
    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        Path artifactPath = null;
        try {
            ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
            ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
            if (artifact != null) {
                artifactPath = artifact.normalizedPath();
            }
        } catch (RuntimeException ignored) {
            artifactPath = null;
        }
        int capped = Math.max(1, Math.min(50, limit));
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(artifactPath, query, Math.max(1, capped - 1));
        ObjectNode summary = JSON.valueToTree(AuthCodeQueryService.toToolMap(result));
        List<FactRecord> records = new ArrayList<>();
        records.add(new FactRecord(scope, "code_query:auth-summary", summary));
        for (AuthCodeQueryService.AuthCodeFact fact : result.facts()) {
            if (records.size() >= capped) break;
            ObjectNode node = JSON.createObjectNode();
            node.put("id", fact.id());
            node.put("category", fact.category());
            node.put("summary", fact.summary());
            node.put("sourcePath", fact.sourcePath());
            node.put("classification", "FACT");
            node.put("verificationStatus", "STATIC_INFERRED");
            node.set("attributes", JSON.valueToTree(fact.attributes()));
            records.add(new FactRecord(scope, "code_query:" + fact.id(), node));
        }
        return List.copyOf(records);
    }

    @Override
    public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                        String query, int limit) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        String requested = kind.toUpperCase(Locale.ROOT);
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<FactRecord> result = new ArrayList<>();
        if ("SCAN".equals(requested) || "METADATA".equals(requested) || "ANY".equals(requested)) {
            addIfMatching(result, scope, "scan:" + scan.dto().scanId(),
                    JSON.valueToTree(scan.dto()), needle, limit);
        }
        if ("ENTRY".equals(requested) || "ENTRYPOINT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EntryDto value : scan.dto().entries()) {
                addIfMatching(result, scope, "entry:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("DEPENDENCY".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.DependencyDto value : scan.dto().dependencies()) {
                addIfMatching(result, scope, "dependency:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("SINK".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.SinkDto value : scan.dto().sinks()) {
                addIfMatching(result, scope, "sink:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("PATH_RUN".equals(requested) || "PATHRUN".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.PathRunDto value : pathRuns(scan)) {
                addIfMatching(result, scope, "pathrun:" + value.pathRunId(), pathRunFact(value), needle, limit);
            }
        }
        if ("STATIC_CONTRAST".equals(requested) || "CONTRAST".equals(requested) || "ANY".equals(requested)) {
            ContrastLedger.Ledger ledger = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), pathRuns(scan));
            for (StaticContrastRow row : ledger.rows()) {
                addIfMatching(result, scope, "contrast:" + row.rowId(),
                        ContrastLedger.toFactNode(row), needle, limit);
            }
        }
        if ("EVIDENCE".equals(requested) || "FACT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EvidenceDto value : scan.evidence().values()) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
            for (ApiDtos.EvidenceDto value : dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
        }
        if ("DYNAMIC_EVIDENCE".equals(requested) || "RUNTIME_EVIDENCE".equals(requested)) {
            for (ApiDtos.EvidenceDto value : dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
        }
        return List.copyOf(result);
    }

    @Override
    public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        ApiDtos.EvidenceDto value = scan.evidence().get(evidenceRef);
        if (value != null) {
            return Optional.of(new FactRecord(scope, value.evidenceId(), safeEvidence(value)));
        }
        Optional<ApiDtos.EvidenceDto> dynamic = dynamicEvidence(scan).stream()
                .filter(item -> item.evidenceId().equals(evidenceRef)).findFirst();
        if (dynamic.isPresent()) {
            return Optional.of(new FactRecord(scope, evidenceRef, safeEvidence(dynamic.get())));
        }
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), evidenceRef);
        if (resolution.resolved()) {
            return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                    JSON.valueToTree(resolution.entry())));
        }
        if (evidenceRef != null && evidenceRef.startsWith("pathrun:")) {
            String id = evidenceRef.substring("pathrun:".length());
            return pathRuns(scan).stream().filter(run -> run.pathRunId().equals(id)).findFirst()
                    .map(run -> new FactRecord(scope, evidenceRef, pathRunFact(run)));
        }
        return Optional.empty();
    }

    @Override
    public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (!resolution.resolved()) {
            if (resolution.status() == EntryRefResolver.Status.AMBIGUOUS) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_AMBIGUOUS);
            }
            if (resolution.status() == EntryRefResolver.Status.MUST_BE_ENTRY) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_MUST_BE_ENTRY);
            }
            return Optional.empty();
        }
        return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                JSON.valueToTree(resolution.entry())));
    }

    @Override
    public Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                    String principalId, String jobId,
                                                    String entrypointRef,
                                                    List<String> candidateInputs,
                                                    int maxRequests,
                                                    String techniqueId,
                                                    String authorizationHeader,
                                                    String bladeAuthHeader) throws Exception {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        ApiDtos.EntryDto entry = requireProbeEntry(scan, entrypointRef);
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null || entry.method() == null) {
            throw new IllegalArgumentException("sandbox probe entry is not an eligible HTTP endpoint");
        }
        String canonical = EntryRefResolver.canonicalRef(entry);
        return dynamicProbeExecutor.request(scanId, scope, principalId, jobId, canonical,
                candidateInputs == null ? List.of() : List.copyOf(candidateInputs), maxRequests,
                techniqueId, authorizationHeader, bladeAuthHeader);
    }

    @Override
    public void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan) {
        scopedScan(scope);
        experimentPlanAcceptor.accept(scanId, plan);
    }

    private ControlPlaneStore.ScanRecord scopedScan(ToolExecutionContext.Scope scope) {
        if (!"local".equals(scope.workspaceId())) throw new SecurityException("workspace scope mismatch");
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("project scope mismatch");
        }
        return scan;
    }

    private List<ApiDtos.EvidenceDto> dynamicEvidence(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.EvidenceDto> values = List.copyOf(dynamicEvidenceSource.evidenceForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 10_000 || values.stream().anyMatch(value ->
                !dto.projectId().equals(value.projectId())
                        || !dto.artifactDigest().equals(value.artifactDigest())
                        || !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("dynamic evidence scope mismatch");
        }
        return values;
    }

    private List<ApiDtos.PathRunDto> pathRuns(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> values = List.copyOf(pathRunSource.pathRunsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 50_000 || values.stream().anyMatch(value -> !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("path run scope mismatch");
        }
        return values;
    }

    private static ApiDtos.EntryDto requireProbeEntry(ControlPlaneStore.ScanRecord scan, String entrypointRef) {
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (resolution.resolved()) {
            return resolution.entry();
        }
        throw new IllegalArgumentException(resolution.code());
    }

    private static JsonNode pathRunFact(ApiDtos.PathRunDto value) {
        ObjectNode node = JSON.createObjectNode();
        node.put("kind", "PATH_RUN");
        node.put("pathRunId", value.pathRunId());
        node.put("scanId", value.scanId());
        node.put("entrypointRef", value.entrypointRef());
        node.put("track", value.track());
        node.put("attemptId", value.attemptId());
        if (value.experimentPlanId() != null && !value.experimentPlanId().isBlank()) {
            node.put("experimentPlanId", value.experimentPlanId());
        }
        node.put("method", value.method());
        node.put("contentType", value.contentType());
        node.put("requestSummary", value.requestSummary());
        node.put("outcomeClass", value.outcomeClass());
        node.put("httpStatus", value.httpStatus());
        if (value.entryHit() != null) node.put("entryHit", value.entryHit());
        if (value.parameterBound() != null) node.put("parameterBound", value.parameterBound());
        node.put("stopReason", value.stopReason());
        node.put("verificationStatus", value.verificationStatus());
        node.put("identityProvenance", value.identityProvenance());
        node.put("identityPrecondition", value.identityPrecondition());
        ArrayNode evidenceRefs = node.putArray("evidenceRefs");
        for (String ref : value.evidenceRefs()) evidenceRefs.add(ref);
        ArrayNode sqlEvents = node.putArray("sqlEvents");
        int emitted = 0;
        for (ApiDtos.SqlEventDto sql : value.sqlEvents()) {
            if (emitted >= MAX_SQL_EVENTS_IN_FACT) break;
            ObjectNode row = sqlEvents.addObject();
            String sqlText = sql.sqlText() == null ? "" : sql.sqlText();
            if (sqlText.length() > MAX_SQL_TEXT) sqlText = sqlText.substring(0, MAX_SQL_TEXT);
            row.put("sqlText", sqlText);
            row.put("parameterSummary", sql.parameterSummary() == null ? "" : sql.parameterSummary());
            row.put("readWrite", sql.readWrite());
            row.put("parameterized", sql.parameterized());
            row.put("maliciousFragmentPresent", sql.maliciousFragmentPresent());
            row.put("captureMode", sql.captureMode());
            emitted++;
        }
        node.put("sqlEventCount", value.sqlEvents().size());
        node.put("sqlEventsTruncated", value.sqlEvents().size() > MAX_SQL_EVENTS_IN_FACT);
        return node;
    }

    private static JsonNode safeEvidence(ApiDtos.EvidenceDto value) {
        // Only the bounded evidence summary and provenance metadata cross the tool boundary.
        return JSON.createObjectNode()
                .put("evidenceId", value.evidenceId())
                .put("projectId", value.projectId())
                .put("artifactDigest", value.artifactDigest())
                .put("scanId", value.scanId())
                .put("provenanceKind", value.provenanceKind())
                .put("source", value.source())
                .put("summary", value.summary())
                .put("verificationStatus", value.verificationStatus())
                .put("dependencyMode", value.dependencyMode());
    }

    private static void addIfMatching(List<FactRecord> result, ToolExecutionContext.Scope scope,
                                      String reference, JsonNode value, String needle, int limit) {
        if (result.size() >= limit) return;
        String searchable = value.toString().toLowerCase(Locale.ROOT);
        if (needle.isEmpty() || searchable.contains(needle)) {
            result.add(new FactRecord(scope, reference, value));
        }
    }

    /** Compact HTTP/SQL digest used when injecting PathRuns into AI prompts. */
    public static Map<String, Object> pathRunPromptSummary(ApiDtos.PathRunDto value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("pathRunId", value.pathRunId());
        row.put("entrypointRef", value.entrypointRef());
        row.put("track", value.track());
        row.put("method", value.method());
        row.put("httpStatus", value.httpStatus());
        row.put("outcomeClass", value.outcomeClass());
        row.put("verificationStatus", value.verificationStatus());
        row.put("requestSummary", truncate(value.requestSummary(), 160));
        row.put("sqlEventCount", value.sqlEvents().size());
        List<Map<String, Object>> sql = new ArrayList<>();
        int emitted = 0;
        for (ApiDtos.SqlEventDto event : value.sqlEvents()) {
            if (emitted >= 3) break;
            Map<String, Object> sqlRow = new LinkedHashMap<>();
            sqlRow.put("readWrite", event.readWrite());
            sqlRow.put("captureMode", event.captureMode());
            sqlRow.put("maliciousFragmentPresent", event.maliciousFragmentPresent());
            sqlRow.put("sqlText", truncate(event.sqlText(), 120));
            sql.add(sqlRow);
            emitted++;
        }
        row.put("sqlEvents", sql);
        return row;
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    @FunctionalInterface
    public interface DynamicEvidenceSource {
        List<ApiDtos.EvidenceDto> evidenceForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface DynamicProbeExecutor {
        Optional<FactRecord> request(String scanId, ToolExecutionContext.Scope scope, String principalId, String jobId,
                                     String entrypointRef, List<String> candidateInputs, int maxRequests,
                                     String techniqueId, String authorizationHeader, String bladeAuthHeader)
                throws Exception;
    }

    @FunctionalInterface
    public interface PathRunSource {
        List<ApiDtos.PathRunDto> pathRunsForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface ExperimentPlanAcceptor {
        void accept(String scanId, ExperimentPlan plan);
    }
}
