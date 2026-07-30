package com.aq.jvmsentinel.analysis.spi;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.ir.SanitizerNode;
import com.aq.jvmsentinel.domain.ir.TrustBoundaryNode;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 校验 provider 输出：schema、scope、budget、dedupe。
 * 拒绝 Finding 写与 verification-status 提升。
 */
public final class ProviderOutputGate {
    private static final Set<String> FORBIDDEN_STATUS = Set.of(
            "VERIFIED", "DYNAMIC_CONFIRMED", "DYNAMIC_SUSPECTED");
    private static final Set<String> ALLOWED_STATUS = Set.of(
            "STATIC_INFERRED", "UNREACHED", "");

    private final ProviderContext context;
    private final List<String> rejected = new ArrayList<>();
    private final List<String> truncateReasons = new ArrayList<>();
    private final Set<String> seenEntryIds = new LinkedHashSet<>();
    private final Set<String> seenEffectIds = new LinkedHashSet<>();
    private final Set<String> seenGuardIds = new LinkedHashSet<>();
    private final Set<String> seenTrustIds = new LinkedHashSet<>();
    private final Set<String> seenSanitizerIds = new LinkedHashSet<>();
    private final Set<String> seenMethodKeys = new LinkedHashSet<>();
    private final Set<String> seenHypothesisIds = new LinkedHashSet<>();
    private final Set<String> seenPlanIds = new LinkedHashSet<>();

    private final List<ProviderContribution.ArtifactNodes> artifacts = new ArrayList<>();
    private final List<ProviderContribution.Entry> entries = new ArrayList<>();
    private final List<ProviderContribution.TrustBoundary> trustBoundaries = new ArrayList<>();
    private final List<ProviderContribution.Effect> effects = new ArrayList<>();
    private final List<ProviderContribution.Guard> guards = new ArrayList<>();
    private final List<ProviderContribution.Sanitizer> sanitizers = new ArrayList<>();
    private final List<ProviderContribution.MethodSummary> methodSummaries = new ArrayList<>();
    private final List<ProviderContribution.Detector> detectors = new ArrayList<>();
    private final List<ProviderContribution.DynamicProbe> probes = new ArrayList<>();

    public ProviderOutputGate(ProviderContext context) {
        this.context = Objects.requireNonNull(context, "context");
    }

    public void acceptArtifacts(ProviderContribution.ArtifactNodes contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        int nodeCount = contribution.classes().size() + contribution.dependencies().size();
        if (artifacts.stream().mapToInt(a -> a.classes().size() + a.dependencies().size()).sum() + nodeCount
                > context.budget().maxArtifactNodes()) {
            truncateReasons.add("artifact nodes capped at " + context.budget().maxArtifactNodes());
            return;
        }
        artifacts.add(contribution);
    }

    public void acceptEntry(ProviderContribution.Entry contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        EntryNode node = clampEntry(contribution.node(), contribution.providerId());
        if (node == null) return;
        if (entries.size() >= context.budget().maxEntries()) {
            truncateReasons.add("entries capped at " + context.budget().maxEntries());
            return;
        }
        if (!seenEntryIds.add(node.id())) {
            rejected.add("dedupe:entry:" + node.id());
            return;
        }
        entries.add(new ProviderContribution.Entry(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(), node));
    }

    public void acceptTrustBoundary(ProviderContribution.TrustBoundary contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        TrustBoundaryNode node = contribution.node();
        contribution = new ProviderContribution.TrustBoundary(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(),
                new TrustBoundaryNode(node.id(), node.boundaryKind(), node.name(), node.entryNodeId(),
                        node.evidenceRefs(), "INFERENCE"));
        if (trustBoundaries.size() >= context.budget().maxTrustBoundaries()) {
            truncateReasons.add("trustBoundaries capped at " + context.budget().maxTrustBoundaries());
            return;
        }
        if (!seenTrustIds.add(node.id())) {
            rejected.add("dedupe:trust:" + node.id());
            return;
        }
        trustBoundaries.add(contribution);
    }

    public void acceptEffect(ProviderContribution.Effect contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        EffectNode node = clampEffect(contribution.node(), contribution.providerId());
        if (node == null) return;
        if (effects.size() >= context.budget().maxEffects()) {
            truncateReasons.add("effects capped at " + context.budget().maxEffects());
            return;
        }
        if (!seenEffectIds.add(node.id())) {
            rejected.add("dedupe:effect:" + node.id());
            return;
        }
        effects.add(new ProviderContribution.Effect(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(),
                node, contribution.custom()));
    }

    public void acceptGuard(ProviderContribution.Guard contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        GuardNode node = contribution.node();
        contribution = new ProviderContribution.Guard(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(),
                new GuardNode(node.id(), node.guardKind(), node.expression(), node.subjectNodeId(),
                        node.evidenceRefs(), "INFERENCE"));
        if (guards.size() >= context.budget().maxGuards()) {
            truncateReasons.add("guards capped at " + context.budget().maxGuards());
            return;
        }
        if (!seenGuardIds.add(node.id())) {
            rejected.add("dedupe:guard:" + node.id());
            return;
        }
        guards.add(contribution);
    }

    public void acceptSanitizer(ProviderContribution.Sanitizer contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        SanitizerNode node = contribution.node();
        contribution = new ProviderContribution.Sanitizer(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(),
                new SanitizerNode(node.id(), node.sanitizerKind(), node.symbol(), node.evidenceRefs(),
                        "INFERENCE"));
        if (sanitizers.size() >= context.budget().maxSanitizers()) {
            truncateReasons.add("sanitizers capped at " + context.budget().maxSanitizers());
            return;
        }
        if (!seenSanitizerIds.add(node.id())) {
            rejected.add("dedupe:sanitizer:" + node.id());
            return;
        }
        sanitizers.add(contribution);
    }

    public void acceptMethodSummary(ProviderContribution.MethodSummary contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        if (methodSummaries.size() >= context.budget().maxMethodSummaries()) {
            truncateReasons.add("methodSummaries capped at " + context.budget().maxMethodSummaries());
            return;
        }
        if (!seenMethodKeys.add(contribution.methodKey())) {
            rejected.add("dedupe:method:" + contribution.methodKey());
            return;
        }
        methodSummaries.add(contribution);
    }

    public void acceptDetector(ProviderContribution.Detector contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        SecurityHypothesis hyp = contribution.hypothesis();
        if (hyp == null) return;
        if (!context.scanId().equals(hyp.scanId())) {
            rejected.add("scope:detector-scan-mismatch:" + contribution.providerId());
            return;
        }
        if (detectors.size() >= context.budget().maxDetectors()) {
            truncateReasons.add("detectors capped at " + context.budget().maxDetectors());
            return;
        }
        if (!seenHypothesisIds.add(hyp.hypothesisId())) {
            rejected.add("dedupe:detector:" + hyp.hypothesisId());
            return;
        }
        // 强制 CANDIDATE — provider 不能提升 lifecycle / 写 Finding。
        SecurityHypothesis clamped = new SecurityHypothesis(
                hyp.schemaVersion(),
                hyp.hypothesisId(),
                hyp.scanId(),
                hyp.securityProperty(),
                hyp.family(),
                HypothesisLifecycle.CANDIDATE,
                hyp.detectorVersion(),
                hyp.supportingEvidenceRefs(),
                hyp.contradictingEvidenceRefs(),
                hyp.coverageGapRefs(),
                hyp.source(),
                hyp.effect());
        detectors.add(new ProviderContribution.Detector(
                contribution.providerId(), contribution.declaredScope(), contribution.schemaVersion(),
                contribution.projectId(), contribution.artifactDigest(), contribution.scanId(),
                clamped));
    }

    public void acceptProbe(ProviderContribution.DynamicProbe contribution) {
        if (contribution == null) return;
        if (!scopeOk(contribution.schemaVersion(), contribution.projectId(),
                contribution.artifactDigest(), contribution.scanId(), contribution.providerId())) {
            return;
        }
        if (probes.size() >= context.budget().maxProbes()) {
            truncateReasons.add("probes capped at " + context.budget().maxProbes());
            return;
        }
        if (!seenPlanIds.add(contribution.plan().planId())) {
            rejected.add("dedupe:probe:" + contribution.plan().planId());
            return;
        }
        probes.add(contribution);
    }

    /** Explicit rejection helper for Finding / status elevation attempts. */
    public void rejectForbidden(String reason) {
        rejected.add(Objects.requireNonNullElse(reason, "forbidden"));
    }

    public ProviderBundle build() {
        return new ProviderBundle(
                AnalysisProvider.SCHEMA_VERSION,
                context.projectId(),
                context.artifactDigest(),
                context.scanId(),
                artifacts, entries, trustBoundaries, effects, guards, sanitizers,
                methodSummaries, detectors, probes, rejected, truncateReasons);
    }

    private boolean scopeOk(int schemaVersion, String projectId, String artifactDigest,
                            String scanId, String providerId) {
        if (schemaVersion != AnalysisProvider.SCHEMA_VERSION) {
            rejected.add("schema:" + providerId + ":v" + schemaVersion);
            return false;
        }
        if (!context.projectId().equals(projectId)
                || !context.artifactDigest().equals(artifactDigest)
                || !context.scanId().equals(scanId)) {
            rejected.add("scope:" + providerId);
            return false;
        }
        return true;
    }

    private EntryNode clampEntry(EntryNode node, String providerId) {
        String status = normalizeStatus(node.verificationStatus());
        if (FORBIDDEN_STATUS.contains(status)) {
            rejected.add("status-elevation:entry:" + providerId + ":" + status);
            status = "STATIC_INFERRED";
        } else if (!ALLOWED_STATUS.contains(status)) {
            status = "STATIC_INFERRED";
        }
        return new EntryNode(
                node.id(), node.protocol(), node.operation(), node.address(),
                node.declaringSymbol(), node.inputs(), node.evidenceRefs(),
                "INFERENCE", status);
    }

    private EffectNode clampEffect(EffectNode node, String providerId) {
        String status = normalizeStatus(node.verificationStatus());
        if (FORBIDDEN_STATUS.contains(status)) {
            rejected.add("status-elevation:effect:" + providerId + ":" + status);
            status = "STATIC_INFERRED";
        } else if (!ALLOWED_STATUS.contains(status)) {
            status = "STATIC_INFERRED";
        }
        return new EffectNode(
                node.id(), node.category(), node.symbol(), node.sourceLabel(),
                node.evidenceRefs(), "INFERENCE", status);
    }

    private static String normalizeStatus(String status) {
        return status == null ? "" : status.trim().toUpperCase(Locale.ROOT);
    }
}
