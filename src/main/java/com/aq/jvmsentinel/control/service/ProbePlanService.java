package com.aq.jvmsentinel.control.service;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.service.probe.ProbeAiPocMaterializer;
import com.aq.jvmsentinel.control.service.probe.ProbeAiPocPlanner;
import com.aq.jvmsentinel.control.service.probe.ProbeExperimentStamper;
import com.aq.jvmsentinel.control.service.probe.ProbeFloodPlanBuilder;
import com.aq.jvmsentinel.control.service.probe.ProbeFloodSelector;
import com.aq.jvmsentinel.control.service.probe.ProbeIdentityExpander;
import com.aq.jvmsentinel.control.service.probe.ProbePlanPayloadCodec;
import com.aq.jvmsentinel.control.service.probe.ProbePostureExpander;
import com.aq.jvmsentinel.control.service.probe.ProbeTracePlanSupport;
import com.aq.jvmsentinel.control.service.probe.ProbeWireHelpers;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * 服务端动态探针计划门面：洪水选择、AI PoC materialization、identity-track 展开。
 * 自 ControlPlaneServer 抽出以便独立测试；实现委托 {@code control.service.probe} 辅助类。
 */
public final class ProbePlanService {
    /** 洪水探针上限；与 worker/agent/sandbox 上传预算共享。 */
    public static final int MAX_DYNAMIC_PROBES = ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES;
    /** 序列化 TSV 上传预算；须与可信沙箱 {@code uploadFile} 一致。 */
    public static final int MAX_PROBE_PLAN_UPLOAD_BYTES =
            ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES;
    /** 持久化 JSON 探针计划 payload 上限（primary + probes + unreached paths）。 */
    public static final int MAX_PROBE_PLAN_PAYLOAD_BYTES = 8 * 1024 * 1024;

    private final ControlPlaneStore store;
    private final BiFunction<String, String, List<TaskSnapshot>> workerSnapshots;
    private final ProbeTracePlanSupport traceSupport;
    private final ProbePostureExpander postureExpander;

    public ProbePlanService(ControlPlaneStore store,
                            BiFunction<String, String, List<TaskSnapshot>> workerSnapshots) {
        this.store = Objects.requireNonNull(store, "store");
        this.workerSnapshots = Objects.requireNonNull(workerSnapshots, "workerSnapshots");
        this.traceSupport = new ProbeTracePlanSupport(store);
        this.postureExpander = new ProbePostureExpander(store);
    }

    public static final class TargetEntryNotInScanException extends RuntimeException {
        public TargetEntryNotInScanException(String message) {
            super(message);
        }
    }

    public ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint) {
        return buildProbePlan(scan, taskIdHint, null, List.of(), MAX_DYNAMIC_PROBES, null, null, null, null);
    }

    public ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId) {
        return buildProbePlan(scan, taskIdHint, preferredEntryId, List.of(), MAX_DYNAMIC_PROBES,
                null, null, null, null);
    }

    public ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests) {
        return buildProbePlan(scan, taskIdHint, preferredEntryId, candidateInputs, requestedMaxRequests,
                null, null, null, null);
    }

    public ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests, String techniqueId,
                                     String authorizationHeader, Path artifactPath) {
        return buildProbePlan(scan, taskIdHint, preferredEntryId, candidateInputs, requestedMaxRequests,
                techniqueId, authorizationHeader, null, artifactPath);
    }

    public ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests, String techniqueId,
                                     String authorizationHeader, String bladeAuthHeader,
                                     Path artifactPath) {
        List<ApiDtos.EntryDto> httpEntries = ProbeFloodPlanBuilder.filterHttpProbeEntries(scan);
        if (httpEntries.isEmpty()) {
            return new ProbePlan(null, List.of(), List.of());
        }
        boolean focusedPoc = preferredEntryId != null
                && ((authorizationHeader != null && !authorizationHeader.isBlank())
                || (bladeAuthHeader != null && !bladeAuthHeader.isBlank())
                || (techniqueId != null && !techniqueId.isBlank()));
        if (focusedPoc) {
            return ProbeAiPocPlanner.buildFocusedAiPocPlan(
                    scanProjection(scan), httpEntries, preferredEntryId, candidateInputs,
                    requestedMaxRequests, techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
        }
        int maxProbes = MAX_DYNAMIC_PROBES;
        ProbeFloodPlanBuilder.FloodSelection selection = ProbeFloodPlanBuilder.selectBaseProbes(
                scan, httpEntries, taskIdHint, preferredEntryId, candidateInputs, requestedMaxRequests,
                maxProbes, workerSnapshots, traceSupport, pathExplorationHintText(scan));
        ApiDtos.EntryDto primary = selection.primary();
        LinkedHashSet<String> selectedIds = selection.selectedIds();
        List<ExternalArtifactTaskExecutor.ProbeTarget> effectiveProbes = selection.effectiveProbes();
        IdentityExpansionResult expansion;
        Path postureArtifact = artifactPath;
        if (postureArtifact == null) {
            postureArtifact = resolveArtifactPath(scan);
        }
        PostureExpansionResult postureExpansion = expandProbesByPostureDetailed(
                scan, httpEntries, effectiveProbes, true, maxProbes, postureArtifact);
        if (!postureExpansion.probes().isEmpty()) {
            effectiveProbes = ProbeWireHelpers.rejectEmptyCoverageWithoutPlan(postureExpansion.probes());
            expansion = new IdentityExpansionResult(effectiveProbes, postureExpansion.unreached());
        } else {
            expansion = expandProbesByIdentityTracksDetailed(scan, httpEntries, effectiveProbes, maxProbes);
            effectiveProbes = ProbeExperimentStamper.stampExperimentPlanIds(
                    store, scan, httpEntries, expansion.probes());
        }
        List<ApiDtos.PathDto> unreached = new ArrayList<>(expansion.identityUnreached());
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (selectedIds.contains(entry.id())) continue;
            unreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, scan.dto().projectId(), scan.dto().artifactDigest(),
                    scan.dto().scanId(),
                    "path-unreached-" + scan.dto().scanId() + "-" + entry.id(),
                    entry.id(), ApiDtos.UNREACHED, ApiDtos.MOCK,
                    entry.preconditions(), "PROBE_BUDGET_EXHAUSTED", List.of(),
                    List.of(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                            "超出本次断网探针预算，未动态刺激", "entry", "blocked", entry.evidenceRefs()))));
        }
        return new ProbePlan(primary, List.copyOf(effectiveProbes), List.copyOf(unreached));
    }

    PostureExpansionResult expandProbesByPostureDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            boolean dockerSandbox,
            int maxProbes) {
        return expandProbesByPostureDetailed(scan, httpEntries, base, dockerSandbox, maxProbes, null);
    }

    PostureExpansionResult expandProbesByPostureDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            boolean dockerSandbox,
            int maxProbes,
            Path artifactPath) {
        ProbePostureExpander.PostureExpansionResult result = postureExpander.expandProbesByPostureDetailed(
                scan, httpEntries, base, dockerSandbox, maxProbes, artifactPath);
        return new PostureExpansionResult(result.probes(), result.unreached());
    }

    public record PostureExpansionResult(List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                                         List<ApiDtos.PathDto> unreached) {
        public PostureExpansionResult {
            probes = List.copyOf(probes == null ? List.of() : probes);
            unreached = List.copyOf(unreached == null ? List.of() : unreached);
        }
    }

    /**
     * 供验收测试使用：MISSING_AUTH / AI PoC materialization。
     * {@code bladeAuthToken} 为 secondary auth 通道 token（已弃用 wire 名；语义为 {@code secondaryAuthToken}）。
     */
    public record AuthMaterialized(IdentityTrack track, String authToken, String bladeAuthToken,
                                   String provenance, boolean identityAvailable) {
        public AuthMaterialized(IdentityTrack track, String authToken, String provenance) {
            this(track, authToken, "", provenance, true);
        }

        /** secondary auth 通道 token 的通用别名。 */
        public String secondaryAuthToken() {
            return bladeAuthToken == null ? "" : bladeAuthToken;
        }

        static AuthMaterialized from(ProbeAiPocMaterializer.AuthMaterialized materialized) {
            return new AuthMaterialized(
                    materialized.track(),
                    materialized.authToken(),
                    materialized.bladeAuthToken(),
                    materialized.provenance(),
                    materialized.identityAvailable());
        }
    }

    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, Path artifactPath) {
        return materializeAiPocAuth(techniqueId, authorizationHeader, null, artifactPath);
    }

    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, Path artifactPath) {
        return AuthMaterialized.from(ProbeAiPocMaterializer.materializeAiPocAuth(
                techniqueId, authorizationHeader, bladeAuthHeader, artifactPath));
    }

    public record ProbePlan(ApiDtos.EntryDto primary,
                            List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                            List<ApiDtos.PathDto> unreachedPaths) {
    }

    public static String serializePlanPayload(ProbePlan plan) {
        return ProbePlanPayloadCodec.serializePlanPayload(plan);
    }

    public static ProbePlan hydrateFromStoredPayload(String payloadJson) {
        return ProbePlanPayloadCodec.hydrateFromStoredPayload(payloadJson);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record StoredProbePlanPayload(
            int schemaVersion,
            ApiDtos.EntryDto primary,
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
            List<ApiDtos.PathDto> unreachedPaths) {
    }

    public static ExternalArtifactTaskExecutor.ProbeTarget probeTargetFor(ApiDtos.EntryDto entry) {
        return ProbeWireHelpers.probeTargetFor(entry);
    }

    public List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return expandProbesByIdentityTracksDetailed(scan, httpEntries, base, maxProbes).probes();
    }

    public IdentityExpansionResult expandProbesByIdentityTracksDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        ProbeIdentityExpander.IdentityExpansionResult result =
                ProbeIdentityExpander.expandProbesByIdentityTracksDetailed(
                        store, scan, httpEntries, base, maxProbes);
        return new IdentityExpansionResult(result.probes(), result.identityUnreached());
    }

    public static List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            Path artifactPath,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return ProbeIdentityExpander.expandProbesByIdentityTracks(
                artifactPath, httpEntries, base, maxProbes);
    }

    public record IdentityExpansionResult(List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                                            List<ApiDtos.PathDto> identityUnreached) {
        public IdentityExpansionResult {
            probes = List.copyOf(probes == null ? List.of() : probes);
            identityUnreached = List.copyOf(identityUnreached == null ? List.of() : identityUnreached);
        }
    }

    public static IdentityExpansionResult expandProbesByIdentityTracksDetailed(
            String projectId, String artifactDigest, String scanId,
            Path artifactPath,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        ProbeIdentityExpander.IdentityExpansionResult result =
                ProbeIdentityExpander.expandProbesByIdentityTracksDetailed(
                        projectId, artifactDigest, scanId, artifactPath, httpEntries, base, maxProbes);
        return new IdentityExpansionResult(result.probes(), result.identityUnreached());
    }

    static List<ExternalArtifactTaskExecutor.ProbeTarget> rejectEmptyCoverageWithoutPlan(
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        return ProbeWireHelpers.rejectEmptyCoverageWithoutPlan(probes);
    }

    static boolean materialsPreferSecondaryAuth(
            ProbeIdentityExpander.TrackExpansion expansion,
            com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService.SyntheticIdentity synth) {
        return ProbeIdentityExpander.materialsPreferSecondaryAuth(expansion, synth);
    }

    /** @deprecated 使用 {@link #materialsPreferSecondaryAuth}。 */
    @Deprecated
    static boolean materialsPreferBladeAuth(
            ProbeIdentityExpander.TrackExpansion expansion,
            com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService.SyntheticIdentity synth) {
        return ProbeIdentityExpander.materialsPreferBladeAuth(expansion, synth);
    }

    static String normalizeProbeToken(String authorizationHeader) {
        return ProbeWireHelpers.normalizeProbeToken(authorizationHeader);
    }

    static boolean isHighValueEntry(ApiDtos.EntryDto entry) {
        return ProbeWireHelpers.isHighValueEntry(entry);
    }

    static boolean isHighValueRoute(String route) {
        return ProbeWireHelpers.isHighValueRoute(route);
    }

    public static boolean containsHighValueSignal(String value) {
        return ProbeWireHelpers.containsHighValueSignal(value);
    }

    public static String materializeRoute(String route) {
        return ProbeWireHelpers.materializeRoute(route);
    }

    static IdentityTrack identityTrackFromWire(String track) {
        return ProbeWireHelpers.identityTrackFromWire(track);
    }

    static String sanitizeExperimentPlanId(String experimentPlanId) {
        return ProbeWireHelpers.sanitizeExperimentPlanId(experimentPlanId);
    }

    static String sanitizeQuery(String query) {
        return ProbeWireHelpers.sanitizeQuery(query);
    }

    static String syntheticQuery(ApiDtos.EntryDto entry) {
        return ProbeWireHelpers.syntheticQuery(entry);
    }

    static List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbeTargets(
            ApiDtos.EntryDto entry, List<String> candidateInputs, int requestedMaxRequests) {
        return ProbeFloodSelector.candidateProbeTargets(entry, candidateInputs, requestedMaxRequests);
    }

    private static ProbeAiPocPlanner.ControlPlaneStoreScan scanProjection(ControlPlaneStore.ScanRecord scan) {
        return new ProbeAiPocPlanner.ControlPlaneStoreScan(
                scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId());
    }

    private Path resolveArtifactPath(ControlPlaneStore.ScanRecord scan) {
        try {
            ArtifactDescriptor artifact = store.artifact(
                    store.requireProject(scan.dto().projectId()), scan.dto().artifactDigest());
            if (artifact != null) {
                return artifact.normalizedPath();
            }
        } catch (RuntimeException ignored) {
            // 无 artifact 时 posture/identity 展开仍可做 UNAUTH 路径
        }
        return null;
    }

    /** 不可信 PATH_EXPLORATION 结论文本，仅用于探针排序优先级。 */
    private String pathExplorationHintText(ControlPlaneStore.ScanRecord scan) {
        try {
            return store.aiJobs(scan.dto().projectId()).stream()
                    .filter(job -> scan.dto().scanId().equals(job.scanId()))
                    .filter(job -> job.role() == com.aq.jvmsentinel.provider.AgentRole.PATH_EXPLORATION)
                    .filter(job -> "COMPLETED".equals(job.status()) && job.conclusionJson() != null)
                    .map(job -> job.conclusionJson())
                    .findFirst()
                    .orElse("");
        } catch (RuntimeException ignored) {
            return "";
        }
    }
}
