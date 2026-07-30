package com.aq.jvmsentinel.analysis.spi;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.ir.SanitizerNode;
import com.aq.jvmsentinel.domain.ir.TrustBoundaryNode;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.aq.jvmsentinel.model.ExperimentPlan;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 类型化 provider 输出。Finding 写与 verification 提升被 gate 拒绝。
 */
public final class ProviderContribution {
    private ProviderContribution() {
    }

    public record ArtifactNodes(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            List<ArtifactUniverse.ClassNode> classes,
            List<ArtifactUniverse.DependencySummary> dependencies,
            List<CoverageGap> coverageGaps,
            List<String> stopReasons
    ) {
        public ArtifactNodes {
            Objects.requireNonNull(providerId, "providerId");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
            classes = List.copyOf(classes == null ? List.of() : classes);
            dependencies = List.copyOf(dependencies == null ? List.of() : dependencies);
            coverageGaps = List.copyOf(coverageGaps == null ? List.of() : coverageGaps);
            stopReasons = List.copyOf(stopReasons == null ? List.of() : stopReasons);
        }
    }

    public record Entry(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            EntryNode node
    ) {
        public Entry {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(node, "node");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }

    public record TrustBoundary(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            TrustBoundaryNode node
    ) {
        public TrustBoundary {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(node, "node");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }

    public record Effect(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            EffectNode node,
            boolean custom
    ) {
        public Effect {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(node, "node");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }

    public record Guard(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            GuardNode node
    ) {
        public Guard {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(node, "node");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }

    public record Sanitizer(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            SanitizerNode node
    ) {
        public Sanitizer {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(node, "node");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }

    public record MethodSummary(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            String methodKey,
            String summaryKind,
            List<String> effects,
            List<String> evidenceRefs,
            String coverageStatus,
            String stopReason
    ) {
        public MethodSummary {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(methodKey, "methodKey");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
            summaryKind = summaryKind == null || summaryKind.isBlank() ? "UNKNOWN" : summaryKind;
            effects = List.copyOf(effects == null ? List.of() : effects);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            coverageStatus = coverageStatus == null || coverageStatus.isBlank() ? "PARTIAL" : coverageStatus;
            stopReason = stopReason == null ? "" : stopReason;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("methodKey", methodKey);
            map.put("summaryKind", summaryKind);
            map.put("effects", effects);
            map.put("evidenceRefs", evidenceRefs);
            map.put("coverageStatus", coverageStatus);
            map.put("stopReason", stopReason);
            map.put("providerId", providerId);
            return map;
        }
    }

    /**
     * Detector 输出仅为 {@link SecurityHypothesis} 候选 — 永非 Finding，
     * lifecycle 由 gate 钳制为 {@link HypothesisLifecycle#CANDIDATE}。
     */
    public record Detector(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            SecurityHypothesis hypothesis
    ) {
        public Detector {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(hypothesis, "hypothesis");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }

        public HypothesisFamily family() {
            return hypothesis.family();
        }
    }

    public record DynamicProbe(
            String providerId,
            String declaredScope,
            int schemaVersion,
            String projectId,
            String artifactDigest,
            String scanId,
            ExperimentPlan plan
    ) {
        public DynamicProbe {
            Objects.requireNonNull(providerId, "providerId");
            Objects.requireNonNull(plan, "plan");
            declaredScope = declaredScope == null || declaredScope.isBlank() ? providerId : declaredScope;
        }
    }
}
