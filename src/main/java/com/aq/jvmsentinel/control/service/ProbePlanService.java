package com.aq.jvmsentinel.control.service;

import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.analysis.experiment.EntryParameterExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.GuardSurfaceCatalog;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.ProbeParameterHeuristics;
import com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestrator;
import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.TracePlanObservationDiff;
import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackManifest;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * Builds server-owned dynamic probe plans: flood selection, AI-focused PoC materialization,
 * and identity-track expansion. Extracted from ControlPlaneServer for independent testing.
 */
public final class ProbePlanService {
    /** Flood probe ceiling; shared with worker/agent/sandbox upload budget. */
    public static final int MAX_DYNAMIC_PROBES = ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES;
    /** Serialized TSV upload budget; must match trusted-sandbox {@code uploadFile}. */
    public static final int MAX_PROBE_PLAN_UPLOAD_BYTES =
            ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES;
    /** Bound for durable JSON probe-plan payloads (primary + probes + unreached paths). */
    public static final int MAX_PROBE_PLAN_PAYLOAD_BYTES = 8 * 1024 * 1024;
    private static final int STORED_PROBE_PLAN_SCHEMA = 1;
    private static final ObjectMapper PAYLOAD_JSON = new ObjectMapper();

    private final ControlPlaneStore store;
    private final BiFunction<String, String, List<TaskSnapshot>> workerSnapshots;

    public ProbePlanService(ControlPlaneStore store,
                            BiFunction<String, String, List<TaskSnapshot>> workerSnapshots) {
        this.store = Objects.requireNonNull(store, "store");
        this.workerSnapshots = Objects.requireNonNull(workerSnapshots, "workerSnapshots");
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
        List<ApiDtos.EntryDto> httpEntries = scan.dto().entries().stream()
                .filter(entry -> NonHttpEntryProtocol.isHttpProbeEligible(entry.protocol()))
                .filter(entry -> entry.route() != null
                        && entry.route().matches("/[A-Za-z0-9_./{}:-]{0,1023}"))
                .filter(entry -> entry.method() != null
                        && (Set.of("GET", "POST", "PUT", "PATCH", "DELETE")
                        .contains(entry.method().toUpperCase(Locale.ROOT))
                        || "UNKNOWN".equalsIgnoreCase(entry.method())))
                .toList();
        if (httpEntries.isEmpty()) {
            return new ProbePlan(null, List.of(), List.of());
        }
        boolean focusedPoc = preferredEntryId != null
                && ((authorizationHeader != null && !authorizationHeader.isBlank())
                || (bladeAuthHeader != null && !bladeAuthHeader.isBlank())
                || (techniqueId != null && !techniqueId.isBlank()));
        if (focusedPoc) {
            return buildFocusedAiPocPlan(scan, httpEntries, preferredEntryId, candidateInputs,
                    requestedMaxRequests, techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
        }
        // Cover discovered HTTP entries, but leave room for identity-track expansion.
        int maxProbes = MAX_DYNAMIC_PROBES;
        int maxBaseProbes = Math.min(httpEntries.size(), maxProbes);
        if (httpEntries.size() >= maxProbes) {
            maxBaseProbes = maxProbes * 3 / 4;
        }
        LinkedHashSet<String> selectedIds = new LinkedHashSet<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes = new ArrayList<>();
        if (preferredEntryId != null) {
            httpEntries.stream().filter(entry -> entry.id().equals(preferredEntryId)).findFirst()
                    .ifPresent(entry -> {
                        selectedIds.add(entry.id());
                        probes.add(probeTargetFor(entry));
                    });
        }
        // Prefer the worker task's target entry when present in the scan.
        if (taskIdHint != null) {
            workerSnapshots.apply(scan.dto().projectId(), scan.dto().scanId()).stream()
                    .filter(snapshot -> snapshot.scope().taskId().equals(taskIdHint))
                    .map(snapshot -> snapshot.spec().targetEntryId())
                    .findFirst()
                    .flatMap(targetId -> httpEntries.stream().filter(entry -> entry.id().equals(targetId)).findFirst())
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) probes.add(probeTargetFor(entry));
                    });
        }
        // Prefer TracePlan gaps (missing expected effects) before generic high-value routes.
        for (String entryId : tracePlanGapEntryIds(scan)) {
            if (probes.size() >= maxBaseProbes) break;
            httpEntries.stream()
                    .filter(entry -> entry.id().equals(entryId))
                    .findFirst()
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) {
                            probes.add(probeTargetFor(entry));
                        }
                    });
        }
        // Prefer entries named by PATH_EXPLORATION / plan_propose inferences (untrusted hints only).
        String explorationHint = pathExplorationHintText(scan);
        if (!explorationHint.isBlank()) {
            for (ApiDtos.EntryDto entry : httpEntries) {
                if (probes.size() >= maxBaseProbes) break;
                if (!(explorationHint.contains(entry.id()) || explorationHint.contains(entry.route()))) {
                    continue;
                }
                if (!selectedIds.add(entry.id())) continue;
                probes.add(probeTargetFor(entry));
            }
        }
        // Prefer entries that static IR already binds to expected effects (sink/taint).
        for (String entryId : staticEffectEntryIds(scan, httpEntries)) {
            if (probes.size() >= maxBaseProbes) break;
            httpEntries.stream()
                    .filter(entry -> entry.id().equals(entryId))
                    .findFirst()
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) {
                            probes.add(probeTargetFor(entry));
                        }
                    });
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (probes.size() >= maxBaseProbes) break;
            if (!isHighValueRoute(entry.route())) continue;
            if (!selectedIds.add(entry.id())) continue;
            probes.add(probeTargetFor(entry));
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (probes.size() >= maxBaseProbes) break;
            if (!selectedIds.add(entry.id())) continue;
            probes.add(probeTargetFor(entry));
        }
        ApiDtos.EntryDto primary = httpEntries.stream()
                .filter(entry -> selectedIds.contains(entry.id()))
                .findFirst()
                .orElse(httpEntries.get(0));
        List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbes = candidateProbeTargets(
                primary, candidateInputs, requestedMaxRequests);
        List<ExternalArtifactTaskExecutor.ProbeTarget> effectiveProbes = probes;
        if (!candidateProbes.isEmpty()) {
            effectiveProbes = candidateProbes;
            selectedIds.clear();
            selectedIds.add(primary.id());
        }
        IdentityExpansionResult expansion;
        Path postureArtifact = artifactPath;
        if (postureArtifact == null) {
            try {
                ArtifactDescriptor artifact = store.artifact(
                        store.requireProject(scan.dto().projectId()), scan.dto().artifactDigest());
                if (artifact != null) {
                    postureArtifact = artifact.normalizedPath();
                }
            } catch (RuntimeException ignored) {
                postureArtifact = null;
            }
        }
        PostureExpansionResult postureExpansion = expandProbesByPostureDetailed(
                scan, httpEntries, effectiveProbes, true, maxProbes, postureArtifact);
        if (!postureExpansion.probes().isEmpty()) {
            effectiveProbes = rejectEmptyCoverageWithoutPlan(postureExpansion.probes());
            expansion = new IdentityExpansionResult(effectiveProbes, postureExpansion.unreached());
        } else {
            expansion = expandProbesByIdentityTracksDetailed(
                    scan, httpEntries, effectiveProbes, maxProbes);
            effectiveProbes = stampExperimentPlanIds(scan, httpEntries, expansion.probes());
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

    /**
     * P0-18/P0-19: stamp server-compiled experimentPlanId onto flood probes so PathRun
     * projection can correlate entry × parameter space without inventing client plans.
     */
    private List<ExternalArtifactTaskExecutor.ProbeTarget> stampExperimentPlanIds(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        if (probes == null || probes.isEmpty()) return List.of();
        List<EntryParameterExperimentCompiler.CompiledExperiment> compiled =
                EntryParameterExperimentCompiler.compileUnified(
                        httpEntries,
                        store.hypotheses(scan.dto().scanId()),
                        List.<ExperimentPlan>of(),
                        List.of(),
                        Math.max(probes.size(), 16));
        Map<String, String> planByKey = new LinkedHashMap<>();
        for (EntryParameterExperimentCompiler.CompiledExperiment item : compiled) {
            if (item == null) continue;
            String key = item.method().toUpperCase(Locale.ROOT) + " " + item.route();
            planByKey.putIfAbsent(key, item.experimentPlanId());
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> stamped = new ArrayList<>(probes.size());
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
            if (probe == null) continue;
            if (probe.experimentPlanId() != null && !probe.experimentPlanId().isBlank()) {
                stamped.add(probe);
                continue;
            }
            String key = probe.method().toUpperCase(Locale.ROOT) + " " + probe.route();
            String planId = planByKey.getOrDefault(key, "");
            stamped.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    probe.method(), probe.route(), probe.query(), probe.track(),
                    probe.authHeader(), probe.bladeAuthHeader(), planId, probe.cookieHeader()));
        }
        return List.copyOf(stamped);
    }

    /**
     * P0-21: compile entry × posture experiment plans and expand probes by posture track wire.
     * FORCED_REACHABILITY is included only when {@code dockerSandbox} is true.
     */
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
        if (base == null || base.isEmpty() || httpEntries == null || httpEntries.isEmpty()) {
            return new PostureExpansionResult(List.of(), List.of());
        }
        LinkedHashSet<String> entryIds = new LinkedHashSet<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : base) {
            httpEntries.stream()
                    .filter(entry -> routeKey(entry).equals(routeKey(probe.method(), probe.route())))
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
        List<GuardSurface> guardSurfaces = harvest.surfaces();
        List<String> guardHints = GuardSurfaceCatalog.guardRefs(guardSurfaces);
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
            String synthetic = syntheticQuery(entry);
            String query = ProbeParameterHeuristics.preferHonestQuery(
                    plan.query(), synthetic, entry.parameters());
            String method = plan.method() == null || plan.method().isBlank()
                    || "UNKNOWN".equalsIgnoreCase(plan.method())
                    ? "GET" : plan.method().toUpperCase(Locale.ROOT);
            String safePlanId = sanitizeExperimentPlanId(plan.experimentPlanId());
            String track = plan.posture().identityTrackWire();
            String auth = "";
            String secondary = "";
            String cookie = "";
            // UNAUTH stays empty; COVERAGE/FORCED/BYPASS carry harvested materials when available.
            if (plan.posture().postureKind() != RuntimePostureKind.UNAUTH) {
                IdentityTrack identityTrack = identityTrackFromWire(track);
                SyntheticIdentityService.SyntheticIdentity synth =
                        identity.synthesize(identityTrack, materials);
                if (synth.available()) {
                    auth = normalizeProbeToken(synth.authorizationHeader());
                    cookie = synth.cookieHeader() == null ? "" : synth.cookieHeader();
                    if (!auth.isBlank() && (materials.preferSecondaryAuthHeader()
                            || materials.multiHeaderAuthSurface())) {
                        secondary = SyntheticIdentityService.secondaryAuthHeaderValue(auth);
                    }
                }
            }
            expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    method,
                    materializeRoute(plan.route()),
                    sanitizeQuery(query),
                    track,
                    auth,
                    secondary,
                    safePlanId,
                    cookie));
        }
        expanded = rejectEmptyCoverageWithoutPlan(expanded);
        return new PostureExpansionResult(List.copyOf(expanded), List.copyOf(unreached));
    }

    private void persistPostureArtifacts(ControlPlaneStore.ScanRecord scan,
                                         List<PostureExperimentCompiler.CompiledPostureExperiment> compiled) {
        persistPostureArtifacts(scan, compiled, GuardSurfaceCatalog.HarvestResult.empty());
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
                    Map<String, Object> payload = new LinkedHashMap<>(tracePlan.toMap());
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
                Map<String, Object> payload = new LinkedHashMap<>(manifest.toMap());
                payload.put("schemaVersion", WorldPackManifest.SCHEMA_VERSION);
                store.persistWorldPack(new SQLiteControlPlanePersistence.WorldPackData(
                        manifest.worldPackId(), scan.dto().scanId(), scan.dto().projectId(),
                        scan.dto().artifactDigest(), manifest.dependencyMode().name(),
                        JsonCodec.stringify(payload), createdAt));
            }
            Map<String, Object> payload = new LinkedHashMap<>(plan.toWireMap());
            payload.put("schemaVersion", 1);
            if (harvest != null && harvest.truncated()
                    && plan.posture().postureKind() == RuntimePostureKind.FORCED_REACHABILITY) {
                // Visible gap: allowlist may omit walls when MAX_TYPE_NAMES / MAX_SURFACES caps hit.
                payload.put("guardCatalogGap", GuardSurfaceCatalog.GAP_CATALOG_TRUNCATED);
            }
            store.persistExperimentPlan(new SQLiteControlPlanePersistence.ExperimentPlanData(
                    plan.experimentPlanId(), scan.dto().scanId(), scan.dto().projectId(),
                    scan.dto().artifactDigest(), JsonCodec.stringify(payload), createdAt));
        }
    }

    /** Reject empty GET/POST probes without experimentPlanId as primary coverage (P0-18/P0-21). */
    static List<ExternalArtifactTaskExecutor.ProbeTarget> rejectEmptyCoverageWithoutPlan(
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        if (probes == null || probes.isEmpty()) return List.of();
        List<ExternalArtifactTaskExecutor.ProbeTarget> kept = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
            if (probe == null) continue;
            boolean getOrPost = "GET".equals(probe.method()) || "POST".equals(probe.method());
            boolean emptyInput = probe.query() == null || probe.query().isBlank();
            boolean missingPlan = probe.experimentPlanId() == null || probe.experimentPlanId().isBlank();
            if (getOrPost && emptyInput && missingPlan) {
                continue;
            }
            kept.add(probe);
        }
        return List.copyOf(kept);
    }

    private static String routeKey(ApiDtos.EntryDto entry) {
        String method = entry.method() == null || "UNKNOWN".equalsIgnoreCase(entry.method())
                ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        return routeKey(method, entry.route());
    }

    private static String routeKey(String method, String route) {
        return method.toUpperCase(Locale.ROOT) + " " + materializeRoute(route);
    }

    record PostureExpansionResult(List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                                  List<ApiDtos.PathDto> unreached) {
        PostureExpansionResult {
            probes = List.copyOf(probes == null ? List.of() : probes);
            unreached = List.copyOf(unreached == null ? List.of() : unreached);
        }
    }

    /** Converts only bounded name=value hints into URL query data for the selected entry. */
    /**
     * Focused DYNAMIC probe for one AI-authored auth PoC. Uses AI authorizationHeader /
     * secondaryAuthorizationHeader (wire alias: bladeAuthHeader) independently when present;
     * otherwise falls back to a known {@link AuthBypassTechnique} synthesizer.
     */
    private ProbePlan buildFocusedAiPocPlan(
            ControlPlaneStore.ScanRecord scan,
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
                .orElseThrow(() -> new TargetEntryNotInScanException("AI PoC entry is not in the scan"));
        String method = primary.method() == null || "UNKNOWN".equalsIgnoreCase(primary.method())
                ? "GET" : primary.method().toUpperCase(Locale.ROOT);
        String route = materializeRoute(primary.route());
        String query = syntheticQuery(primary);
        List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbes =
                candidateProbeTargets(primary, candidateInputs, requestedMaxRequests);
        if (!candidateProbes.isEmpty()) {
            query = candidateProbes.get(0).query();
        }
        AuthMaterialized materialized = materializeAiPocAuth(
                techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
        List<ApiDtos.PathDto> unreached = new ArrayList<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes;
        if (!materialized.identityAvailable()) {
            // Keep intentional UNAUTH stimulus; do not attach empty tokens to ADMIN/USER.
            probes = List.of(new ExternalArtifactTaskExecutor.ProbeTarget(
                    method, route, query, IdentityTrack.UNAUTH.name(), "", ""));
            unreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, scan.dto().projectId(), scan.dto().artifactDigest(),
                    scan.dto().scanId(),
                    "path-unreached-" + scan.dto().scanId() + "-" + primary.id()
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
                    ApiDtos.SCHEMA_VERSION, scan.dto().projectId(), scan.dto().artifactDigest(),
                    scan.dto().scanId(),
                    "path-unreached-" + scan.dto().scanId() + "-" + entry.id(),
                    entry.id(), ApiDtos.UNREACHED, ApiDtos.MOCK,
                    entry.preconditions(), "FOCUSED_AI_POC", List.of(),
                    List.of(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                            "本次仅执行 AI PoC 焦点探针，未批量刺激", "entry", "blocked", entry.evidenceRefs()))));
        }
        return new ProbePlan(primary, probes, List.copyOf(unreached));
    }

    /**
     * Package-visible for acceptance tests of MISSING_AUTH / AI PoC materialization.
     * {@code bladeAuthToken} is the secondary auth-channel token (deprecated wire name;
     * semantically {@code secondaryAuthToken}).
     */
    public record AuthMaterialized(IdentityTrack track, String authToken, String bladeAuthToken,
                            String provenance, boolean identityAvailable) {
        AuthMaterialized(IdentityTrack track, String authToken, String provenance) {
            this(track, authToken, "", provenance, true);
        }

        /** Generic alias for the secondary auth-channel token. */
        public String secondaryAuthToken() {
            return bladeAuthToken == null ? "" : bladeAuthToken;
        }
    }

    /** Package-visible for acceptance tests of MISSING_AUTH / AI PoC materialization. */
    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, Path artifactPath) {
        return materializeAiPocAuth(techniqueId, authorizationHeader, null, artifactPath);
    }

    /** Package-visible for acceptance tests of MISSING_AUTH / AI PoC materialization. */
    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, Path artifactPath) {
        Optional<AuthBypassTechnique> technique = AuthBypassTechnique.tryParse(techniqueId);
        String secondaryToken = normalizeProbeToken(bladeAuthHeader);
        if (!secondaryToken.isEmpty()) {
            AuthBypassCandidate.validateAuthMaterialOnly(bladeAuthHeader);
        }
        // MISSING_AUTH is an intentional unauthenticated probe: never invent Bearer / secondary auth.
        if (technique.isPresent() && technique.get() == AuthBypassTechnique.MISSING_AUTH) {
            if ((authorizationHeader != null && !authorizationHeader.isBlank()) || !secondaryToken.isEmpty()) {
                throw new IllegalArgumentException("MISSING_AUTH_MUST_OMIT_AUTHORIZATION");
            }
            return new AuthMaterialized(IdentityTrack.UNAUTH, "", "", "MISSING_AUTH", true);
        }
        boolean hasAuth = authorizationHeader != null && !authorizationHeader.isBlank();
        if (hasAuth || !secondaryToken.isEmpty()) {
            String authToken = "";
            if (hasAuth) {
                AuthBypassCandidate.validateAuthMaterialOnly(authorizationHeader);
                authToken = normalizeProbeToken(authorizationHeader);
            }
            // AI-authored DEFAULT_SECRET_HS256 may dual-write secondary channel when harvest says so.
            if (secondaryToken.isEmpty()
                    && technique.isPresent()
                    && technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                    && !authToken.isBlank()
                    && artifactPath != null) {
                SyntheticIdentityService.MaterialBundle harvested =
                        new SyntheticIdentityService().harvest(artifactPath);
                if (harvested.preferSecondaryAuthHeader() || harvested.multiHeaderAuthSurface()) {
                    secondaryToken = SyntheticIdentityService.secondaryAuthHeaderValue(authToken);
                }
            } else if (secondaryToken.isEmpty()
                    && technique.isPresent()
                    && technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                    && !authToken.isBlank()) {
                // No artifact context: keep Authorization-only (generic default).
            }
            IdentityTrack track = technique
                    .map(AuthBypassTechnique::defaultTrack)
                    .orElse(IdentityTrack.BYPASS_CANDIDATE);
            return new AuthMaterialized(track, authToken, secondaryToken, "AI_POC", true);
        }
        if (technique.isEmpty() || technique.get() == AuthBypassTechnique.CUSTOM_POC) {
            return new AuthMaterialized(IdentityTrack.BYPASS_CANDIDATE, "", "", "AI_POC_NO_MATERIAL", true);
        }
        SyntheticIdentityService identity = new SyntheticIdentityService();
        SyntheticIdentityService.MaterialBundle materials = identity.harvest(artifactPath);
        SyntheticIdentityService.SyntheticIdentity synth =
                identity.synthesizeTechnique(technique.get(), materials);
        if (!synth.available()) {
            return new AuthMaterialized(technique.get().defaultTrack(), "", "",
                    synth.precondition(), false);
        }
        String token = normalizeProbeToken(synth.authorizationHeader());
        String secondary = "";
        if (!token.isBlank() && (technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                && (materials.preferSecondaryAuthHeader() || materials.multiHeaderAuthSurface()))) {
            secondary = SyntheticIdentityService.secondaryAuthHeaderValue(token);
        }
        // ALG_NONE / EMPTY_BEARER: keep channels independent unless AI supplied secondary auth.
        if (technique.get() == AuthBypassTechnique.ALG_NONE
                || technique.get() == AuthBypassTechnique.EMPTY_BEARER) {
            secondary = "";
        }
        return new AuthMaterialized(synth.track(), token, secondary, synth.provenance(), true);
    }

    private static List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbeTargets(
            ApiDtos.EntryDto entry, List<String> candidateInputs, int requestedMaxRequests) {
        if (candidateInputs == null || candidateInputs.isEmpty()) return List.of();
        int limit = Math.max(1, Math.min(8, requestedMaxRequests));
        List<String> parameterNames = entry.parameters() == null ? List.of() : entry.parameters().stream()
                .map(ProbePlanService::parameterName).filter(Objects::nonNull).limit(12).toList();
        List<ExternalArtifactTaskExecutor.ProbeTarget> result = new ArrayList<>();
        for (String candidate : candidateInputs) {
            if (result.size() >= limit || candidate == null || candidate.length() > 1024) break;
            String name;
            String value;
            int separator = candidate.indexOf('=');
            if (separator > 0) {
                name = candidate.substring(0, separator);
                value = candidate.substring(separator + 1);
            } else if (!parameterNames.isEmpty()) {
                name = parameterNames.get(Math.min(result.size(), parameterNames.size() - 1));
                value = candidate;
            } else {
                continue;
            }
            if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") || value.length() > 512
                    || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)
                    || parameterNames.isEmpty() || !parameterNames.contains(name)) continue;
            String encoded = java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
            result.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    entry.method() == null || "UNKNOWN".equalsIgnoreCase(entry.method())
                            ? "GET" : entry.method().toUpperCase(Locale.ROOT),
                    materializeRoute(entry.route()), name + "=" + encoded));
        }
        return List.copyOf(result);
    }

    private static String parameterName(String parameter) {
        String name = ProbeParameterHeuristics.resolveName(parameter);
        return name.isBlank() ? null : name;
    }

    public record ProbePlan(ApiDtos.EntryDto primary,
                             List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                             List<ApiDtos.PathDto> unreachedPaths) {
    }

    /**
     * Serialize a compiled probe plan for durable restore. Does not harvest or rebuild.
     */
    public static String serializePlanPayload(ProbePlan plan) {
        Objects.requireNonNull(plan, "plan");
        if (plan.primary() == null) {
            throw new IllegalArgumentException("probe plan primary entry is required");
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes =
                plan.probes() == null ? List.of() : plan.probes();
        if (probes.isEmpty() || probes.size() > MAX_DYNAMIC_PROBES) {
            throw new IllegalArgumentException("probe plan probe count is out of bounds");
        }
        try {
            String json = PAYLOAD_JSON.writeValueAsString(new StoredProbePlanPayload(
                    STORED_PROBE_PLAN_SCHEMA, plan.primary(), probes,
                    plan.unreachedPaths() == null ? List.of() : plan.unreachedPaths()));
            if (json.length() > MAX_PROBE_PLAN_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("probe plan payload exceeds durable size budget");
            }
            return json;
        } catch (IllegalArgumentException invalid) {
            throw invalid;
        } catch (Exception failure) {
            throw new IllegalArgumentException("probe plan payload could not be serialized", failure);
        }
    }

    /**
     * Hydrate an in-memory probe plan from a stored payload without identity harvest.
     * Returns {@code null} when the payload is absent (legacy rows); throws when corrupt.
     */
    public static ProbePlan hydrateFromStoredPayload(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) {
            return null;
        }
        if (payloadJson.length() > MAX_PROBE_PLAN_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("probe plan payload exceeds durable size budget");
        }
        try {
            StoredProbePlanPayload stored = PAYLOAD_JSON.readValue(payloadJson, StoredProbePlanPayload.class);
            if (stored == null || stored.schemaVersion() != STORED_PROBE_PLAN_SCHEMA) {
                throw new IllegalArgumentException("unsupported probe plan payload schema");
            }
            if (stored.primary() == null) {
                throw new IllegalArgumentException("probe plan payload missing primary entry");
            }
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes =
                    stored.probes() == null ? List.of() : List.copyOf(stored.probes());
            if (probes.isEmpty() || probes.size() > MAX_DYNAMIC_PROBES) {
                throw new IllegalArgumentException("probe plan payload probe count is out of bounds");
            }
            // Reconstruct ProbeTarget through the validating constructor (fail closed).
            List<ExternalArtifactTaskExecutor.ProbeTarget> validated = new ArrayList<>(probes.size());
            for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
                if (probe == null) {
                    throw new IllegalArgumentException("probe plan payload contains a null probe");
                }
                validated.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                        probe.method(), probe.route(), probe.query(), probe.track(),
                        probe.authHeader(), probe.bladeAuthHeader(), probe.experimentPlanId(),
                        probe.cookieHeader()));
            }
            List<ApiDtos.PathDto> unreached = stored.unreachedPaths() == null
                    ? List.of() : List.copyOf(stored.unreachedPaths());
            return new ProbePlan(stored.primary(), List.copyOf(validated), unreached);
        } catch (IllegalArgumentException invalid) {
            throw invalid;
        } catch (Exception failure) {
            throw new IllegalArgumentException("probe plan payload is corrupt or incomplete", failure);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record StoredProbePlanPayload(
            int schemaVersion,
            ApiDtos.EntryDto primary,
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
            List<ApiDtos.PathDto> unreachedPaths) {
    }

    public static ExternalArtifactTaskExecutor.ProbeTarget probeTargetFor(ApiDtos.EntryDto entry) {
        String method = entry.method() == null ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        if ("UNKNOWN".equals(method)) method = "GET";
        return new ExternalArtifactTaskExecutor.ProbeTarget(
                method, materializeRoute(entry.route()), syntheticQuery(entry), "UNAUTH", "");
    }

    /**
     * T2+T3: high-value entries probe all synthesizable tracks; others UNAUTH + ADMIN when available.
     * Total probes remain capped by {@code maxProbes}. Unavailable synth tracks become
     * {@code IDENTITY_UNAVAILABLE} unreached paths instead of empty-auth probes.
     */
    public List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return expandProbesByIdentityTracksDetailed(scan, httpEntries, base, maxProbes).probes();
    }

    private IdentityExpansionResult expandProbesByIdentityTracksDetailed(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        if (base == null || base.isEmpty()) {
            return new IdentityExpansionResult(List.of(), List.of());
        }
        Path artifactPath = null;
        try {
            ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
            ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
            if (artifact != null) artifactPath = artifact.normalizedPath();
        } catch (RuntimeException ignored) {
            artifactPath = null;
        }
        return expandProbesByIdentityTracksDetailed(
                scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId(),
                artifactPath, httpEntries, base, maxProbes);
    }

    public static List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            Path artifactPath,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return expandProbesByIdentityTracksDetailed(
                "project-test", "a".repeat(64), "scan-test",
                artifactPath, httpEntries, base, maxProbes).probes();
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
        if (base == null || base.isEmpty()) {
            return new IdentityExpansionResult(List.of(), List.of());
        }
        SyntheticIdentityService identity = new SyntheticIdentityService();
        SyntheticIdentityService.MaterialBundle materials = identity.harvest(artifactPath);
        Map<String, ApiDtos.EntryDto> byRoute = new LinkedHashMap<>();
        for (ApiDtos.EntryDto entry : httpEntries) {
            byRoute.putIfAbsent(materializeRoute(entry.route()), entry);
        }
        List<TrackExpansion> expansions = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : base) {
            ApiDtos.EntryDto entry = byRoute.get(probe.route());
            boolean highValue = isHighValueRoute(probe.route()) || (entry != null && isHighValueEntry(entry));
            expansions.add(new TrackExpansion(probe, entry,
                    tracksFor(identity, materials, highValue), highValue));
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> expanded = new ArrayList<>();
        List<ApiDtos.PathDto> identityUnreached = new ArrayList<>();
        int unauthCoverageLimit = expansions.size() >= maxProbes ? Math.max(1, maxProbes * 3 / 4) : maxProbes;
        for (TrackExpansion expansion : expansions) {
            if (expanded.size() >= unauthCoverageLimit) break;
            addTrackProbe(expanded, identityUnreached, projectId, artifactDigest, scanId,
                    expansion, expansion.tracks().get(0), maxProbes);
        }
        for (TrackExpansion expansion : expansions) {
            if (expanded.size() >= maxProbes) break;
            if (!expansion.highValue()) continue;
            for (int trackIndex = 1; trackIndex < expansion.tracks().size(); trackIndex++) {
                if (expanded.size() >= maxProbes) break;
                addTrackProbe(expanded, identityUnreached, projectId, artifactDigest, scanId,
                        expansion, expansion.tracks().get(trackIndex), maxProbes);
            }
        }
        int maxTrackCount = expansions.stream().mapToInt(expansion -> expansion.tracks().size()).max().orElse(1);
        for (int trackIndex = 1; trackIndex < maxTrackCount && expanded.size() < maxProbes; trackIndex++) {
            for (TrackExpansion expansion : expansions) {
                if (expanded.size() >= maxProbes) break;
                if (expansion.highValue() || trackIndex >= expansion.tracks().size()) continue;
                addTrackProbe(expanded, identityUnreached, projectId, artifactDigest, scanId,
                        expansion, expansion.tracks().get(trackIndex), maxProbes);
            }
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes =
                List.copyOf(expanded.isEmpty() ? base : expanded);
        return new IdentityExpansionResult(probes, identityUnreached);
    }

    private record TrackExpansion(ExternalArtifactTaskExecutor.ProbeTarget probe,
                                  ApiDtos.EntryDto entry,
                                  List<SyntheticIdentityService.SyntheticIdentity> tracks,
                                  boolean highValue) {
        private TrackExpansion {
            tracks = List.copyOf(tracks);
            if (tracks.isEmpty()) throw new IllegalArgumentException("at least UNAUTH track is required");
        }
    }

    private static List<SyntheticIdentityService.SyntheticIdentity> tracksFor(
            SyntheticIdentityService identity,
            SyntheticIdentityService.MaterialBundle materials,
            boolean highValue) {
        List<IdentityTrack> desired = highValue
                ? List.of(IdentityTrack.UNAUTH, IdentityTrack.USER, IdentityTrack.ADMIN, IdentityTrack.BYPASS_CANDIDATE)
                : List.of(IdentityTrack.UNAUTH, IdentityTrack.ADMIN);
        List<SyntheticIdentityService.SyntheticIdentity> result = new ArrayList<>();
        for (IdentityTrack track : desired) {
            // Keep unavailable tracks so callers can emit IDENTITY_UNAVAILABLE (not silent skip).
            result.add(identity.synthesize(track, materials));
        }
        return List.copyOf(result);
    }

    private static void addTrackProbe(List<ExternalArtifactTaskExecutor.ProbeTarget> expanded,
                                      List<ApiDtos.PathDto> identityUnreached,
                                      String projectId, String artifactDigest, String scanId,
                                      TrackExpansion expansion,
                                      SyntheticIdentityService.SyntheticIdentity synth,
                                      int maxProbes) {
        if (expanded.size() >= maxProbes) return;
        ExternalArtifactTaskExecutor.ProbeTarget probe = expansion.probe();
        if (!synth.available()) {
            if (synth.track() == IdentityTrack.UNAUTH) {
                expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                        probe.method(), probe.route(), probe.query(), "UNAUTH", "", ""));
                return;
            }
            ApiDtos.EntryDto entry = expansion.entry();
            String entryId = entry != null ? entry.id()
                    : ("entry-route-" + Integer.toHexString(probe.route().hashCode()));
            List<String> evidenceRefs = entry != null ? entry.evidenceRefs() : List.of();
            String reason = synth.precondition() == null || synth.precondition().isBlank()
                    ? "IDENTITY_UNAVAILABLE" : synth.precondition();
            identityUnreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    "path-unreached-" + scanId + "-" + entryId + "-" + synth.track().name(),
                    entryId, ApiDtos.UNREACHED, ApiDtos.MOCK,
                    List.of(reason), "IDENTITY_UNAVAILABLE", List.of(),
                    List.of(new ApiDtos.PathStepDto(
                            synth.track().name() + " " + probe.method() + " " + probe.route(),
                            "synthetic identity unavailable; probe skipped",
                            "branch", "blocked", evidenceRefs))));
            return;
        }
        String token = normalizeProbeToken(synth.authorizationHeader());
        // Dual-write secondary auth header when framework-adapter / harvest marks multi-header surface.
        String secondary = "";
        if (!token.isBlank() && materialsPreferSecondaryAuth(expansion, synth)) {
            secondary = SyntheticIdentityService.secondaryAuthHeaderValue(token);
        }
        String cookie = synth.cookieHeader() == null ? "" : synth.cookieHeader();
        expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                probe.method(), probe.route(), probe.query(),
                synth.track().name(), token, secondary, "", cookie));
    }

    /**
     * Dual-write secondary auth when harvest precondition or a matched FrameworkAdapter
     * prefers a secondary auth header. Not product-specialized to any single framework.
     */
    static boolean materialsPreferSecondaryAuth(
            TrackExpansion expansion,
            SyntheticIdentityService.SyntheticIdentity synth) {
        if (synth == null || synth.authorizationHeader() == null || synth.authorizationHeader().isBlank()) {
            return false;
        }
        String pre = synth.precondition() == null ? "" : synth.precondition().toLowerCase(Locale.ROOT);
        if (pre.contains("multi-header") || pre.contains("secondary auth")) {
            return true;
        }
        String route = expansion.probe() == null ? "" : expansion.probe().route();
        List<String> routes = route == null || route.isBlank() ? List.of() : List.of(route);
        for (com.aq.jvmsentinel.analysis.framework.FrameworkAdapter adapter
                : com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry.matching(null, routes)) {
            if (adapter.preferSecondaryAuthHeader(null)
                    && adapter.secondaryAuthHeaderName() != null
                    && !adapter.secondaryAuthHeaderName().isBlank()) {
                return true;
            }
        }
        return false;
    }

    /** @deprecated Use {@link #materialsPreferSecondaryAuth}. */
    @Deprecated
    static boolean materialsPreferBladeAuth(
            TrackExpansion expansion,
            SyntheticIdentityService.SyntheticIdentity synth) {
        return materialsPreferSecondaryAuth(expansion, synth);
    }

    /** Strip a leading Bearer scheme for probe Authorization / secondary-auth tokens. */
    static String normalizeProbeToken(String authorizationHeader) {
        if (authorizationHeader == null) return "";
        String token = authorizationHeader.trim();
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return token.substring(7).trim();
        }
        // Preserve intentional blankish material (e.g. EMPTY_BEARER " ") that trim would erase.
        if (token.isEmpty() && !authorizationHeader.isEmpty()) return authorizationHeader;
        return token;
    }

    static boolean isHighValueEntry(ApiDtos.EntryDto entry) {
        return containsHighValueSignal(entry.declaringClass())
                || containsHighValueSignal(entry.module())
                || entry.preconditions().stream().anyMatch(ProbePlanService::containsHighValueSignal)
                || entry.evidenceRefs().stream().anyMatch(ProbePlanService::containsHighValueSignal);
    }

    static boolean isHighValueRoute(String route) {
        return containsHighValueSignal(route);
    }

    public static boolean containsHighValueSignal(String value) {
        return FrameworkAdapterRegistry.containsHighValueSignal(value);
    }

    /** Replace `{pathVar}` templates with a bounded synthetic token for loopback probes. */
    public static String materializeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String materialized = route.replaceAll("\\{[A-Za-z_][A-Za-z0-9_]{0,63}}", "1");
        if (!materialized.matches("/[A-Za-z0-9_./:-]{0,1023}")) {
            throw new IllegalArgumentException("materialized probe route is invalid");
        }
        return materialized;
    }

    /** Keep ProbeTarget.experimentPlanId within wire charset/length. */
    static IdentityTrack identityTrackFromWire(String track) {
        if (track == null || track.isBlank()) {
            return IdentityTrack.ADMIN;
        }
        try {
            return IdentityTrack.valueOf(track.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return IdentityTrack.ADMIN;
        }
    }

    static String sanitizeExperimentPlanId(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) {
            return "";
        }
        String safe = experimentPlanId.trim().replaceAll("[^A-Za-z0-9_.:/-]", "_");
        if (safe.length() > 128) {
            safe = safe.substring(0, 100) + "-" + Integer.toHexString(safe.hashCode());
            if (safe.length() > 128) {
                safe = safe.substring(0, 128);
            }
        }
        return safe.matches("[A-Za-z0-9_.:/-]{1,128}") ? safe : "";
    }

    /** Keep ProbeTarget.query within wire charset/length. */
    static String sanitizeQuery(String query) {
        if (query == null || query.isBlank()) {
            return "";
        }
        String safe = query.trim().replaceAll("[^A-Za-z0-9_=&%./{}:-]", "");
        if (safe.length() > 256) {
            safe = safe.substring(0, 256);
        }
        return safe.matches("[A-Za-z0-9_=&%./{}:-]{1,256}") ? safe : "";
    }

    /** Bounded synthetic query for discovered params (INFERENCE stimulus only). */
    static String syntheticQuery(ApiDtos.EntryDto entry) {
        if (entry == null || entry.parameters() == null || entry.parameters().isEmpty()) {
            return "";
        }
        return ProbeParameterHeuristics.buildSyntheticQuery(entry.parameters(), entry.route());
    }

    /** Untrusted PATH_EXPLORATION conclusion text used only to prioritize probe order. */
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

    /** Entries whose persisted/compiled TracePlan still misses expected effects vs PathTrace. */
    private List<String> tracePlanGapEntryIds(ControlPlaneStore.ScanRecord scan) {
        try {
            List<TracePlan> plans = loadOrCompileTracePlans(scan);
            if (plans.isEmpty()) {
                return List.of();
            }
            List<PathTrace> traces = new ArrayList<>();
            for (SQLiteControlPlanePersistence.PathTraceData row : store.loadPathTracesForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId())) {
                if (row == null) {
                    continue;
                }
                PathTrace cached = store.pathTraceForPathRun(row.pathRunId());
                if (cached != null) {
                    traces.add(cached);
                    continue;
                }
                if (row.payloadJson() != null && !row.payloadJson().isBlank()) {
                    try {
                        traces.add(PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson())));
                    } catch (Exception ignored) {
                        // keep flood selection resilient
                    }
                }
            }
            return TracePlanObservationDiff.entriesWithMissingEffects(
                    TracePlanObservationDiff.prioritizeGaps(
                            TracePlanObservationDiff.diffAll(plans, traces)));
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private List<String> staticEffectEntryIds(
            ControlPlaneStore.ScanRecord scan, List<ApiDtos.EntryDto> httpEntries) {
        try {
            List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                    store.staticFacts(scan.dto().scanId()), scan.dto().sinks());
            return TracePlanCompiler.entryIdsWithExpectedEffects(
                    httpEntries, scan.dto().sinks(), scan.evidence(), taintPaths);
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private List<TracePlan> loadOrCompileTracePlans(ControlPlaneStore.ScanRecord scan) {
        List<TracePlan> plans = new ArrayList<>();
        for (SQLiteControlPlanePersistence.TracePlanData row : store.loadTracePlansForScan(
                scan.dto().scanId())) {
            if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                continue;
            }
            try {
                plans.add(TracePlan.fromMap(JsonCodec.parseObject(row.payloadJson())));
            } catch (Exception ignored) {
                // fall through to compile-from-IR below
            }
        }
        if (!plans.isEmpty()) {
            return List.copyOf(plans);
        }
        List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                store.staticFacts(scan.dto().scanId()), scan.dto().sinks());
        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
            if (entry == null || entry.route() == null || entry.route().isBlank()) {
                continue;
            }
            if (!"HTTP".equalsIgnoreCase(entry.protocol())) {
                continue;
            }
            plans.add(TracePlanCompiler.compileFromStaticIr(
                    entry, scan.dto().sinks(), scan.evidence(), taintPaths, List.of()));
            if (plans.size() >= 64) {
                break;
            }
        }
        return List.copyOf(plans);
    }

}
