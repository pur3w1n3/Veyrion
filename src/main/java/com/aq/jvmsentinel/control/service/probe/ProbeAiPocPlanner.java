package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** 单入口 AI 授权 PoC 焦点探针计划。 */
public final class ProbeAiPocPlanner {
    private ProbeAiPocPlanner() {
    }

    /**
     * 针对单个 AI 编写 auth PoC 的焦点 DYNAMIC 探针。
     * 独立使用 AI authorizationHeader / secondaryAuthorizationHeader（wire 别名 bladeAuthHeader）；
     * 否则回退到已知 {@link com.aq.jvmsentinel.model.AuthBypassTechnique} synthesizer。
     */
    public static ProbePlanService.ProbePlan buildFocusedAiPocPlan(
            ControlPlaneStoreScan scan,
            List<ApiDtos.EntryDto> httpEntries,
            String preferredEntryId,
            List<String> candidateInputs,
            int requestedMaxRequests,
            String techniqueId,
            String authorizationHeader,
            String bladeAuthHeader,
            Path artifactPath) {
        ApiDtos.EntryDto primary = httpEntries.stream()
                .filter(entry -> entry.id().equals(preferredEntryId))
                .findFirst()
                .orElseThrow(() -> new ProbePlanService.TargetEntryNotInScanException(
                        "AI PoC entry is not in the scan"));
        String method = primary.method() == null || "UNKNOWN".equalsIgnoreCase(primary.method())
                ? "GET" : primary.method().toUpperCase(Locale.ROOT);
        String route = ProbeWireHelpers.materializeRoute(primary.route());
        String query = ProbeWireHelpers.syntheticQuery(primary);
        List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbes =
                ProbeFloodSelector.candidateProbeTargets(primary, candidateInputs, requestedMaxRequests);
        if (!candidateProbes.isEmpty()) {
            query = candidateProbes.get(0).query();
        }
        ProbeAiPocMaterializer.AuthMaterialized materialized = ProbeAiPocMaterializer.materializeAiPocAuth(
                techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
        List<ApiDtos.PathDto> unreached = new ArrayList<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes;
        if (!materialized.identityAvailable()) {
            // 保留刻意 UNAUTH 刺激；不向 ADMIN/USER 附加空 token。
            probes = List.of(new ExternalArtifactTaskExecutor.ProbeTarget(
                    method, route, query, IdentityTrack.UNAUTH.name(), "", ""));
            unreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, scan.projectId(), scan.artifactDigest(),
                    scan.scanId(),
                    "path-unreached-" + scan.scanId() + "-" + primary.id()
                            + "-" + materialized.track().name(),
                    primary.id(), ApiDtos.UNREACHED, ApiDtos.MOCK,
                    List.of(materialized.provenance() == null || materialized.provenance().isBlank()
                            ? "IDENTITY_UNAVAILABLE" : materialized.provenance()),
                    "IDENTITY_UNAVAILABLE", List.of(),
                    List.of(new ApiDtos.PathStepDto(
                            materialized.track().name() + " " + method + " " + route,
                            "synthetic identity unavailable; probe skipped",
                            "branch", "blocked", primary.evidenceRefs()))));
        } else {
            probes = List.of(new ExternalArtifactTaskExecutor.ProbeTarget(
                    method, route, query, materialized.track().name(),
                    materialized.authToken(), materialized.bladeAuthToken()));
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (entry.id().equals(primary.id())) continue;
            unreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, scan.projectId(), scan.artifactDigest(),
                    scan.scanId(),
                    "path-unreached-" + scan.scanId() + "-" + entry.id(),
                    entry.id(), ApiDtos.UNREACHED, ApiDtos.MOCK,
                    entry.preconditions(), "FOCUSED_AI_POC", List.of(),
                    List.of(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                            "本次仅执行 AI PoC 焦点探针，未批量刺激", "entry", "blocked", entry.evidenceRefs()))));
        }
        return new ProbePlanService.ProbePlan(primary, probes, List.copyOf(unreached));
    }

    /** 轻量 scan 投影，避免 probe 包直接依赖 ControlPlaneStore.ScanRecord 构造细节。 */
    public record ControlPlaneStoreScan(String projectId, String artifactDigest, String scanId) {
    }
}
