package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.framework.FrameworkAdapter;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** T2+T3：按 identity track 展开探针；高价值入口探测全部可合成 track。 */
public final class ProbeIdentityExpander {
    private ProbeIdentityExpander() {
    }

    public record IdentityExpansionResult(List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                                          List<ApiDtos.PathDto> identityUnreached) {
        public IdentityExpansionResult {
            probes = List.copyOf(probes == null ? List.of() : probes);
            identityUnreached = List.copyOf(identityUnreached == null ? List.of() : identityUnreached);
        }
    }

    public record TrackExpansion(ExternalArtifactTaskExecutor.ProbeTarget probe,
                                 ApiDtos.EntryDto entry,
                                 List<SyntheticIdentityService.SyntheticIdentity> tracks,
                                 boolean highValue) {
        public TrackExpansion {
            tracks = List.copyOf(tracks);
            if (tracks.isEmpty()) throw new IllegalArgumentException("at least UNAUTH track is required");
        }
    }

    public static List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            ControlPlaneStore store,
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return expandProbesByIdentityTracksDetailed(store, scan, httpEntries, base, maxProbes).probes();
    }

    public static IdentityExpansionResult expandProbesByIdentityTracksDetailed(
            ControlPlaneStore store,
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        if (base == null || base.isEmpty()) {
            return new IdentityExpansionResult(List.of(), List.of());
        }
        Path artifactPath = resolveArtifactPath(store, scan);
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
            byRoute.putIfAbsent(ProbeWireHelpers.materializeRoute(entry.route()), entry);
        }
        List<TrackExpansion> expansions = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : base) {
            ApiDtos.EntryDto entry = byRoute.get(probe.route());
            boolean highValue = ProbeWireHelpers.isHighValueRoute(probe.route())
                    || (entry != null && ProbeWireHelpers.isHighValueEntry(entry));
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

    /**
     * harvest 前置条件或匹配的 FrameworkAdapter 偏好 secondary auth 时双写 secondary auth。
     * 不针对任何单一框架做产品特化。
     */
    public static boolean materialsPreferSecondaryAuth(
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
        for (FrameworkAdapter adapter : FrameworkAdapterRegistry.matching(null, routes)) {
            if (adapter.preferSecondaryAuthHeader(null)
                    && adapter.secondaryAuthHeaderName() != null
                    && !adapter.secondaryAuthHeaderName().isBlank()) {
                return true;
            }
        }
        return false;
    }

    /** @deprecated 使用 {@link #materialsPreferSecondaryAuth}。 */
    @Deprecated
    public static boolean materialsPreferBladeAuth(
            TrackExpansion expansion,
            SyntheticIdentityService.SyntheticIdentity synth) {
        return materialsPreferSecondaryAuth(expansion, synth);
    }

    private static Path resolveArtifactPath(ControlPlaneStore store, ControlPlaneStore.ScanRecord scan) {
        try {
            ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
            ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
            if (artifact != null) {
                return artifact.normalizedPath();
            }
        } catch (RuntimeException ignored) {
            // 无 artifact 时仍可做 UNAUTH 展开
        }
        return null;
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
            // 保留不可用 track，便于调用方输出 IDENTITY_UNAVAILABLE（而非静默跳过）。
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
                expanded.add(probe.withAuth("UNAUTH", "", "", ""));
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
        String token = ProbeWireHelpers.normalizeProbeToken(synth.authorizationHeader());
        String secondary = "";
        if (!token.isBlank() && materialsPreferSecondaryAuth(expansion, synth)) {
            secondary = SyntheticIdentityService.secondaryAuthHeaderValue(token);
        }
        String cookie = synth.cookieHeader() == null ? "" : synth.cookieHeader();
        expanded.add(probe.withAuth(synth.track().name(), token, secondary, cookie));
    }
}
