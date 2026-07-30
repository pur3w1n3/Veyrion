package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.experiment.GuardSurfaceCatalog;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.ProbeParameterHeuristics;
import com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestrator;
import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackManifest;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** P0-21：按 posture track wire 编译并展开 entry × posture 实验探针。 */
public final class ProbePostureExpander {
    private final ControlPlaneStore store;

    public ProbePostureExpander(ControlPlaneStore store) {
        this.store = store;
    }

    public record PostureExpansionResult(List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                                         List<ApiDtos.PathDto> unreached) {
        public PostureExpansionResult {
            probes = List.copyOf(probes == null ? List.of() : probes);
            unreached = List.copyOf(unreached == null ? List.of() : unreached);
        }
    }

    /**
     * P0-21：编译 entry × posture 实验计划并按 posture track wire 展开探针。
     * 仅当 {@code dockerSandbox} 为 true 时包含 FORCED_REACHABILITY。
     */
    public PostureExpansionResult expandProbesByPostureDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            boolean dockerSandbox,
            int maxProbes) {
        return expandProbesByPostureDetailed(scan, httpEntries, base, dockerSandbox, maxProbes, null);
    }

    public PostureExpansionResult expandProbesByPostureDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            boolean dockerSandbox,
            int maxProbes,
            Path artifactPath) {
        if (base == null || base.isEmpty() || httpEntries == null || httpEntries.isEmpty()) {
            return new PostureExpansionResult(List.of(), List.of());
        }
        LinkedHashSet<String> entryIds = new LinkedHashSet<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : base) {
            httpEntries.stream()
                    .filter(entry -> ProbeWireHelpers.routeKey(entry)
                            .equals(ProbeWireHelpers.routeKey(probe.method(), probe.route())))
                    .map(ApiDtos.EntryDto::id)
                    .findFirst()
                    .ifPresent(entryIds::add);
        }
        List<ApiDtos.EntryDto> selected = httpEntries.stream()
                .filter(entry -> entryIds.contains(entry.id()))
                .toList();
        if (selected.isEmpty()) {
            return new PostureExpansionResult(List.of(), List.of());
        }
        String scanId = scan.dto().scanId();
        String hint = pathExplorationHintText(scan);
        List<String> bypassCandidates = hint.isBlank() ? List.of() : List.of(hint);
        GuardSurfaceCatalog.HarvestResult harvest = GuardSurfaceCatalog.harvestDetailed(artifactPath);
        List<String> guardHints = GuardSurfaceCatalog.guardRefs(harvest.surfaces());
        List<PostureExperimentCompiler.CompiledPostureExperiment> compiled =
                PostureExperimentCompiler.compileAll(
                        selected, scanId, List.of(), List.of(), guardHints, List.of(),
                        bypassCandidates, Math.max(maxProbes, selected.size() * 4));
        if (compiled.isEmpty()) {
            return new PostureExpansionResult(List.of(), List.of());
        }
        persistPostureArtifacts(scan, compiled, harvest);
        SyntheticIdentityService identity = new SyntheticIdentityService();
        SyntheticIdentityService.MaterialBundle materials = identity.harvest(artifactPath);
        List<ExternalArtifactTaskExecutor.ProbeTarget> expanded = new ArrayList<>();
        List<ApiDtos.PathDto> unreached = new ArrayList<>();
        for (PostureExperimentCompiler.CompiledPostureExperiment plan : compiled) {
            if (expanded.size() >= maxProbes) break;
            if (plan.posture().postureKind() == RuntimePostureKind.FORCED_REACHABILITY) {
                if (!dockerSandbox) continue;
                try {
                    RuntimePostureOrchestrator.authorizeForcedReachability(true, false, Map.of());
                } catch (SecurityException denied) {
                    continue;
                }
            }
            if (plan.posture().postureKind() == RuntimePostureKind.BYPASS && bypassCandidates.isEmpty()) {
                continue;
            }
            ApiDtos.EntryDto entry = selected.stream()
                    .filter(item -> item.id().equals(plan.entryRef()))
                    .findFirst()
                    .orElse(null);
            if (entry == null) continue;
            String synthetic = ProbeWireHelpers.syntheticQuery(entry);
            String query = ProbeParameterHeuristics.preferHonestQuery(
                    plan.query(), synthetic, entry.parameters());
            String method = plan.method() == null || plan.method().isBlank()
                    || "UNKNOWN".equalsIgnoreCase(plan.method())
                    ? "GET" : plan.method().toUpperCase(Locale.ROOT);
            String safePlanId = ProbeWireHelpers.sanitizeExperimentPlanId(plan.experimentPlanId());
            String track = plan.posture().identityTrackWire();
            String auth = "";
            String secondary = "";
            String cookie = "";
            // UNAUTH 保持空；COVERAGE/FORCED/BYPASS 在 harvest 可用时携带 material。
            if (plan.posture().postureKind() != RuntimePostureKind.UNAUTH) {
                IdentityTrack identityTrack = ProbeWireHelpers.identityTrackFromWire(track);
                SyntheticIdentityService.SyntheticIdentity synth =
                        identity.synthesize(identityTrack, materials);
                if (synth.available()) {
                    auth = ProbeWireHelpers.normalizeProbeToken(synth.authorizationHeader());
                    cookie = synth.cookieHeader() == null ? "" : synth.cookieHeader();
                    if (!auth.isBlank() && (materials.preferSecondaryAuthHeader()
                            || materials.multiHeaderAuthSurface())) {
                        secondary = SyntheticIdentityService.secondaryAuthHeaderValue(auth);
                    }
                }
            }
            ExternalArtifactTaskExecutor.ProbeTarget surface =
                    ProbeWireHelpers.probeTargetFor(entry);
            String route = surface.route();
            if (plan.route() != null && !plan.route().isBlank()) {
                // posture 计划 route 优先，但仍保留 entry 合成的 context/port 元数据
                String planned = ProbeWireHelpers.materializeRoute(plan.route());
                if (surface.listenPort() <= 0) {
                    route = planned;
                } else {
                    route = planned.startsWith("/") ? planned : surface.route();
                }
            }
            expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    method,
                    route,
                    ProbeWireHelpers.sanitizeQuery(query),
                    track,
                    auth,
                    secondary,
                    safePlanId,
                    cookie,
                    surface.listenPort()));
        }
        expanded = ProbeWireHelpers.rejectEmptyCoverageWithoutPlan(expanded);
        return new PostureExpansionResult(List.copyOf(expanded), List.copyOf(unreached));
    }

    private void persistPostureArtifacts(ControlPlaneStore.ScanRecord scan,
                                         List<PostureExperimentCompiler.CompiledPostureExperiment> compiled,
                                         GuardSurfaceCatalog.HarvestResult harvest) {
        String createdAt = Instant.now().toString();
        LinkedHashSet<String> traceIds = new LinkedHashSet<>();
        LinkedHashSet<String> worldIds = new LinkedHashSet<>();
        for (PostureExperimentCompiler.CompiledPostureExperiment plan : compiled) {
            store.registerPostureExperiment(plan);
            if (traceIds.add(plan.tracePlanId())) {
                ApiDtos.EntryDto entry = scan.dto().entries().stream()
                        .filter(item -> item.id().equals(plan.entryRef()))
                        .findFirst()
                        .orElse(null);
                if (entry != null) {
                    List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                            store.staticFacts(scan.dto().scanId()), scan.dto().sinks());
                    List<String> guardHints = harvest == null
                            ? List.of() : GuardSurfaceCatalog.guardRefs(harvest.surfaces());
                    TracePlan tracePlan = TracePlanCompiler.compileFromStaticIr(
                            entry, scan.dto().sinks(), scan.evidence(), taintPaths, guardHints);
                    Map<String, Object> payload = new java.util.LinkedHashMap<>(tracePlan.toMap());
                    payload.put("schemaVersion", TracePlan.SCHEMA_VERSION);
                    store.persistTracePlan(new SQLiteControlPlanePersistence.TracePlanData(
                            tracePlan.tracePlanId(), scan.dto().scanId(), scan.dto().projectId(),
                            scan.dto().artifactDigest(), entry.id(), JsonCodec.stringify(payload), createdAt));
                }
            }
            if (worldIds.add(plan.worldPackId())) {
                WorldPackManifest manifest = plan.worldPackId().contains("mock")
                        ? WorldPackPlanner.planMockContinue(scan.dto().scanId())
                        : WorldPackPlanner.planObserveFail(scan.dto().scanId(), List.of());
                Map<String, Object> payload = new java.util.LinkedHashMap<>(manifest.toMap());
                payload.put("schemaVersion", WorldPackManifest.SCHEMA_VERSION);
                store.persistWorldPack(new SQLiteControlPlanePersistence.WorldPackData(
                        manifest.worldPackId(), scan.dto().scanId(), scan.dto().projectId(),
                        scan.dto().artifactDigest(), manifest.dependencyMode().name(),
                        JsonCodec.stringify(payload), createdAt));
            }
            Map<String, Object> payload = new java.util.LinkedHashMap<>(plan.toWireMap());
            payload.put("schemaVersion", 1);
            if (harvest != null && harvest.truncated()
                    && plan.posture().postureKind() == RuntimePostureKind.FORCED_REACHABILITY) {
                // 可见缺口：达到 MAX_TYPE_NAMES / MAX_SURFACES 上限时 allowlist 可能遗漏 wall。
                payload.put("guardCatalogGap", GuardSurfaceCatalog.GAP_CATALOG_TRUNCATED);
            }
            store.persistExperimentPlan(new SQLiteControlPlanePersistence.ExperimentPlanData(
                    plan.experimentPlanId(), scan.dto().scanId(), scan.dto().projectId(),
                    scan.dto().artifactDigest(), JsonCodec.stringify(payload), createdAt));
        }
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
