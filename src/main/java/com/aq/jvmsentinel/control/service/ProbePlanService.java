package com.aq.jvmsentinel.control.service;

import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskSnapshot;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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
        IdentityExpansionResult expansion = expandProbesByIdentityTracksDetailed(
                scan, httpEntries, effectiveProbes, maxProbes);
        effectiveProbes = expansion.probes();
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
        if (parameter == null) return null;
        int nameAt = parameter.indexOf("name=");
        if (nameAt < 0) return null;
        String name = parameter.substring(nameAt + 5).split("[,\\s]", 2)[0].trim();
        return name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") ? name : null;
    }

    public record ProbePlan(ApiDtos.EntryDto primary,
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
        expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                probe.method(), probe.route(), probe.query(),
                synth.track().name(), token, secondary));
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

    /** Bounded synthetic query for discovered params (INFERENCE stimulus only). */
    static String syntheticQuery(ApiDtos.EntryDto entry) {
        if (entry.parameters() == null || entry.parameters().isEmpty()) return "";
        List<String> parts = new ArrayList<>();
        for (String parameter : entry.parameters()) {
            if (parameter == null || parts.size() >= 12) continue;
            int nameAt = parameter.indexOf("name=");
            if (nameAt < 0) continue;
            String name = parameter.substring(nameAt + 5).split("[,\\s]", 2)[0].trim();
            if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if ("businessId".equals(name) || lower.endsWith("id") || lower.endsWith("ids")) {
                parts.add(name + "=1");
            } else {
                parts.add(name + "=synthetic");
            }
        }
        String joined = String.join("&", parts);
        return joined.length() <= 256 ? joined : joined.substring(0, 256);
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

}
