package com.aq.jvmsentinel.analysis.spi.defaults;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.analysis.spi.AnalysisProvider;
import com.aq.jvmsentinel.analysis.spi.ArtifactProvider;
import com.aq.jvmsentinel.analysis.spi.DetectorProvider;
import com.aq.jvmsentinel.analysis.spi.DynamicProbeProvider;
import com.aq.jvmsentinel.analysis.spi.EffectModelProvider;
import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.GuardModelProvider;
import com.aq.jvmsentinel.analysis.spi.MethodSummaryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;
import com.aq.jvmsentinel.analysis.spi.SanitizerModelProvider;
import com.aq.jvmsentinel.analysis.spi.TrustBoundaryProvider;
import com.aq.jvmsentinel.analysis.spi.entry.ExtendedEntryProviders;
import com.aq.jvmsentinel.analysis.kernel.KernelSummaryProjector;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.ir.SanitizerNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.ir.TrustBoundaryNode;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PermissionRequirement;
import com.aq.jvmsentinel.model.Sink;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Thin default JVM providers wrapping existing PreAnalysis / sink / AuthCoverage /
 * AnalysisPack logic. No big-bang rewrite of discovery.
 */
public final class DefaultJvmProviders {
    public static final String ARTIFACT_ID = "default-jvm-artifact";
    public static final String ENTRY_ID = "default-jvm-spring-entry";
    public static final String TRUST_ID = "default-jvm-trust-boundary";
    public static final String EFFECT_ID = "default-jvm-sink-effect";
    public static final String GUARD_ID = "default-jvm-auth-coverage";
    public static final String SANITIZER_ID = "default-jvm-sanitizer";
    public static final String METHOD_SUMMARY_ID = "default-jvm-method-summary";
    public static final String DETECTOR_ID = "default-jvm-sink-detector";
    public static final String PROBE_ID = "default-jvm-analysis-pack-probe";

    private DefaultJvmProviders() {
    }

    public static List<AnalysisProvider> all() {
        List<AnalysisProvider> providers = new ArrayList<>();
        providers.add(new DefaultArtifactProvider());
        providers.add(new DefaultEntryProvider());
        providers.addAll(ExtendedEntryProviders.all());
        providers.add(new DefaultTrustBoundaryProvider());
        providers.add(new DefaultEffectModelProvider());
        providers.add(new DefaultGuardModelProvider());
        providers.add(new DefaultSanitizerModelProvider());
        providers.add(new DefaultMethodSummaryProvider());
        providers.add(new DefaultDetectorProvider());
        providers.add(new DefaultDynamicProbeProvider());
        return List.copyOf(providers);
    }

    static final class DefaultArtifactProvider implements ArtifactProvider {
        @Override public String id() { return ARTIFACT_ID; }
        @Override public String providerVersion() { return "default-jvm-artifact/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.ARTIFACT); }

        @Override
        public List<ProviderContribution.ArtifactNodes> contributeArtifacts(ProviderContext context) {
            if (context.artifact() == null || context.preAnalysis() == null) return List.of();
            List<String> protocols = context.preAnalysis().entryCatalog().entries().stream()
                    .map(Entrypoint::protocol).distinct().toList();
            ArtifactUniverse universe = ArtifactUniverseBuilder.build(
                    context.artifact(), context.preAnalysis().bytecodeFactIndex(), protocols);
            return List.of(new ProviderContribution.ArtifactNodes(
                    id(), declaredScope(), schemaVersion(),
                    context.projectId(), context.artifactDigest(), context.scanId(),
                    universe.classes(), universe.dependencies(), universe.coverageGaps(),
                    universe.truncateReasons()));
        }
    }

    /** Projects Spring / PreAnalysis entry catalog into EntrySurface contributions. */
    static final class DefaultEntryProvider implements EntryProvider {
        @Override public String id() { return ENTRY_ID; }
        @Override public String providerVersion() { return "default-jvm-spring-entry/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.ENTRY); }

        @Override
        public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            List<ProviderContribution.Entry> out = new ArrayList<>();
            for (Entrypoint entry : result.entryCatalog().entries()) {
                if ("AUTH".equalsIgnoreCase(entry.protocol())) continue;
                EntryNode node = new EntryNode(
                        StableNodeIds.entry(entry.id()),
                        entry.protocol(),
                        entry.method(),
                        entry.route(),
                        entry.declaringClass(),
                        entry.parameters(),
                        entry.evidenceRefs(),
                        "FACT",
                        entry.status() == null ? "STATIC_INFERRED" : entry.status().name());
                out.add(new ProviderContribution.Entry(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(), node));
            }
            return out;
        }
    }

    static final class DefaultTrustBoundaryProvider implements TrustBoundaryProvider {
        @Override public String id() { return TRUST_ID; }
        @Override public String providerVersion() { return "default-jvm-trust/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.TRUST_BOUNDARY); }

        @Override
        public List<ProviderContribution.TrustBoundary> contributeTrustBoundaries(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            List<ProviderContribution.TrustBoundary> out = new ArrayList<>();
            for (Entrypoint entry : result.entryCatalog().entries()) {
                if ("AUTH".equalsIgnoreCase(entry.protocol())) continue;
                for (String param : entry.parameters()) {
                    if (param == null || param.isBlank()) continue;
                    TrustBoundaryNode node = new TrustBoundaryNode(
                            StableNodeIds.trust(entry.id(), param),
                            "PARAMETER",
                            param,
                            StableNodeIds.entry(entry.id()),
                            entry.evidenceRefs(),
                            "FACT");
                    out.add(new ProviderContribution.TrustBoundary(
                            id(), declaredScope(), schemaVersion(),
                            context.projectId(), context.artifactDigest(), context.scanId(), node));
                }
            }
            return out;
        }
    }

    /** Projects fixed sink catalog into EffectModel contributions. */
    static final class DefaultEffectModelProvider implements EffectModelProvider {
        @Override public String id() { return EFFECT_ID; }
        @Override public String providerVersion() { return "default-jvm-sink-effect/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.EFFECT_MODEL); }

        @Override
        public List<ProviderContribution.Effect> contributeEffects(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            List<ProviderContribution.Effect> out = new ArrayList<>();
            for (Sink sink : result.sinkCatalog().sinks()) {
                if ("AUTH_GAP".equalsIgnoreCase(sink.category())) continue;
                EffectNode node = new EffectNode(
                        StableNodeIds.effect(sink.id()),
                        sink.category(),
                        sink.symbol(),
                        sink.source(),
                        sink.evidenceRefs(),
                        "FACT",
                        sink.status() == null ? "STATIC_INFERRED" : sink.status().name());
                out.add(new ProviderContribution.Effect(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(),
                        node, false));
            }
            return out;
        }
    }

    /** AuthCoverage: AUTH_GAP sinks + permission matrix → GuardModel. */
    static final class DefaultGuardModelProvider implements GuardModelProvider {
        @Override public String id() { return GUARD_ID; }
        @Override public String providerVersion() { return "default-jvm-auth-coverage/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.GUARD_MODEL); }

        @Override
        public List<ProviderContribution.Guard> contributeGuards(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            List<ProviderContribution.Guard> out = new ArrayList<>();
            for (Sink sink : result.sinkCatalog().sinks()) {
                if (!"AUTH_GAP".equalsIgnoreCase(sink.category())) continue;
                GuardNode node = new GuardNode(
                        StableNodeIds.guard(sink.id()),
                        "AUTH_GAP",
                        sink.symbol(),
                        "",
                        sink.evidenceRefs(),
                        "INFERENCE");
                out.add(new ProviderContribution.Guard(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(), node));
            }
            for (PermissionRequirement perm : result.permissionMatrix().requirements()) {
                String key = "perm-" + perm.entrypointId() + "-"
                        + String.join(",", perm.roles());
                GuardNode node = new GuardNode(
                        StableNodeIds.guard(key),
                        "DECLARED_ROLE",
                        String.join(",", perm.roles()),
                        StableNodeIds.entry(perm.entrypointId()),
                        perm.evidenceRefs(),
                        "FACT");
                out.add(new ProviderContribution.Guard(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(), node));
            }
            return out;
        }
    }

    static final class DefaultSanitizerModelProvider implements SanitizerModelProvider {
        @Override public String id() { return SANITIZER_ID; }
        @Override public String providerVersion() { return "default-jvm-sanitizer/0.2"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.SANITIZER_MODEL); }

        @Override
        public List<ProviderContribution.Sanitizer> contributeSanitizers(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            BytecodeFactIndex index = result.bytecodeFactIndex() == null
                    ? BytecodeFactIndex.EMPTY : result.bytecodeFactIndex();
            List<Sink> sinks = result.sinkCatalog() == null ? List.of() : result.sinkCatalog().sinks();
            List<ProviderContribution.Sanitizer> out = new ArrayList<>();
            int ordinal = 0;
            for (KernelSummaryProjector.SanitizerSeed seed :
                    KernelSummaryProjector.sanitizerSeeds(index, sinks)) {
                ordinal++;
                String key = seed.sanitizerKind() + "-" + ordinal;
                SanitizerNode node = new SanitizerNode(
                        StableNodeIds.sanitizer(key),
                        seed.sanitizerKind(),
                        seed.symbol(),
                        seed.evidenceRefs(),
                        "INFERENCE");
                out.add(new ProviderContribution.Sanitizer(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(), node));
            }
            return List.copyOf(out);
        }
    }

    static final class DefaultMethodSummaryProvider implements MethodSummaryProvider {
        @Override public String id() { return METHOD_SUMMARY_ID; }
        @Override public String providerVersion() { return "default-jvm-method-summary/0.2"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.METHOD_SUMMARY); }

        @Override
        public List<ProviderContribution.MethodSummary> contributeMethodSummaries(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            BytecodeFactIndex index = result.bytecodeFactIndex() == null
                    ? BytecodeFactIndex.EMPTY : result.bytecodeFactIndex();
            List<Sink> sinks = result.sinkCatalog() == null ? List.of() : result.sinkCatalog().sinks();
            List<ProviderContribution.MethodSummary> out = new ArrayList<>();
            for (KernelSummaryProjector.MethodSummarySeed seed :
                    KernelSummaryProjector.methodSummarySeeds(index, sinks)) {
                out.add(new ProviderContribution.MethodSummary(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(),
                        seed.methodKey(),
                        seed.summaryKind(),
                        seed.effects(),
                        seed.evidenceRefs(),
                        seed.coverageStatus(),
                        seed.stopReason()));
            }
            return List.copyOf(out);
        }
    }

    /** Sink → DATAFLOW / AUTH_GAP → GUARD_COVERAGE hypothesis candidates (no Finding write). */
    static final class DefaultDetectorProvider implements DetectorProvider {
        @Override public String id() { return DETECTOR_ID; }
        @Override public String providerVersion() { return SecurityHypothesisProjector.DETECTOR_VERSION; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.DETECTOR); }

        @Override
        public List<ProviderContribution.Detector> contributeDetectors(ProviderContext context) {
            PreAnalysisResult result = context.preAnalysis();
            if (result == null) return List.of();
            List<ProviderContribution.Detector> out = new ArrayList<>();
            int index = 0;
            for (Sink sink : result.sinkCatalog().sinks()) {
                index++;
                boolean authGap = "AUTH_GAP".equalsIgnoreCase(sink.category());
                HypothesisFamily family = authGap ? HypothesisFamily.GUARD_COVERAGE : HypothesisFamily.DATAFLOW;
                String property = authGap ? "AUTH_GAP" : sink.category();
                String source = authGap ? "" : firstOr(sink.source(), "entry-unknown");
                String effect = authGap ? "" : StableNodeIds.effect(sink.id());
                if (!authGap && (source.isBlank() || effect.isBlank())) continue;
                SecurityHypothesis hyp = new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-default-" + index + "-" + sink.id(),
                        context.scanId(),
                        property,
                        family,
                        HypothesisLifecycle.CANDIDATE,
                        providerVersion(),
                        sink.evidenceRefs(),
                        List.of(),
                        List.of(),
                        source,
                        effect);
                out.add(new ProviderContribution.Detector(
                        id(), declaredScope(), schemaVersion(),
                        context.projectId(), context.artifactDigest(), context.scanId(), hyp));
            }
            return out;
        }

        private static String firstOr(String value, String fallback) {
            return value == null || value.isBlank() ? fallback : value;
        }
    }

    /** Blade/Flowable AnalysisPack experiment templates as DynamicProbe contributions. */
    static final class DefaultDynamicProbeProvider implements DynamicProbeProvider {
        @Override public String id() { return PROBE_ID; }
        @Override public String providerVersion() { return "default-jvm-analysis-pack-probe/0.1"; }
        @Override public Set<ProviderKind> kinds() { return EnumSet.of(ProviderKind.DYNAMIC_PROBE); }

        @Override
        public List<ProviderContribution.DynamicProbe> contributeProbes(ProviderContext context) {
            List<ProviderContribution.DynamicProbe> out = new ArrayList<>();
            List<AnalysisPack> packs = AnalysisPackRegistry.matching(
                    context.artifactPath(), context.entryRoutes());
            String entryRef = context.entryRoutes().isEmpty() ? "entry-unknown"
                    : "route:" + context.entryRoutes().get(0);
            for (AnalysisPack pack : packs) {
                for (IdentityTrack track : List.of(IdentityTrack.UNAUTH, IdentityTrack.USER)) {
                    for (ExperimentPlan plan : pack.experimentTemplates(entryRef, track)) {
                        if (plan == null) continue;
                        out.add(new ProviderContribution.DynamicProbe(
                                id(), declaredScope(), schemaVersion(),
                                context.projectId(), context.artifactDigest(), context.scanId(),
                                plan));
                    }
                }
            }
            return out;
        }
    }
}
