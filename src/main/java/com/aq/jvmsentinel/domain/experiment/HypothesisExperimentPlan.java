package com.aq.jvmsentinel.domain.experiment;

import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 绑定 SecurityHypothesis 的服务端 owned experiment plan（P1-06）。
 * AI 可提议 field；仅服务端编译并 gate lifecycle 转换。
 */
public record HypothesisExperimentPlan(
        int schemaVersion,
        String experimentPlanId,
        String hypothesisId,
        String scanId,
        ExperimentPlanKind planKind,
        String entrypointRef,
        IdentityTrack track,
        List<ExperimentSignal> expectedSignals,
        List<ExperimentSignal> counterSignals,
        String stopCondition,
        int maxAttempts,
        String stageAttemptId,
        String probeAttemptId
) {
    public static final int SCHEMA_VERSION = 1;

    public HypothesisExperimentPlan {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        Objects.requireNonNull(experimentPlanId, "experimentPlanId");
        Objects.requireNonNull(hypothesisId, "hypothesisId");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(planKind, "planKind");
        Objects.requireNonNull(track, "track");
        if (experimentPlanId.isBlank()) {
            throw new IllegalArgumentException("experimentPlanId must not be blank");
        }
        if (hypothesisId.isBlank()) {
            throw new IllegalArgumentException("hypothesisId must not be blank");
        }
        if (scanId.isBlank()) {
            throw new IllegalArgumentException("scanId must not be blank");
        }
        entrypointRef = entrypointRef == null ? "" : entrypointRef.trim();
        expectedSignals = List.copyOf(expectedSignals == null ? List.of() : expectedSignals);
        counterSignals = List.copyOf(counterSignals == null ? List.of() : counterSignals);
        stopCondition = stopCondition == null || stopCondition.isBlank() ? "COMPLETED" : stopCondition.trim();
        stageAttemptId = stageAttemptId == null ? "" : stageAttemptId.trim();
        probeAttemptId = probeAttemptId == null ? "" : probeAttemptId.trim();
        if (expectedSignals.isEmpty() && counterSignals.isEmpty()) {
            throw new IllegalArgumentException("plan requires expected or counter signals");
        }
        if (expectedSignals.size() > 16 || counterSignals.size() > 16) {
            throw new IllegalArgumentException("signal lists exceed bound");
        }
        if (maxAttempts < 1 || maxAttempts > 8) {
            throw new IllegalArgumentException("maxAttempts must be 1..8");
        }
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("experimentPlanId", experimentPlanId);
        map.put("hypothesisId", hypothesisId);
        map.put("scanId", scanId);
        map.put("planKind", planKind.name());
        if (!entrypointRef.isBlank()) {
            map.put("entrypointRef", entrypointRef);
        }
        map.put("track", track.name());
        map.put("expectedSignals", expectedSignals.stream().map(ExperimentSignal::code).toList());
        map.put("counterSignals", counterSignals.stream().map(ExperimentSignal::code).toList());
        map.put("stopCondition", stopCondition);
        map.put("maxAttempts", maxAttempts);
        if (!stageAttemptId.isBlank()) {
            map.put("stageAttemptId", stageAttemptId);
        }
        if (!probeAttemptId.isBlank()) {
            map.put("probeAttemptId", probeAttemptId);
        }
        map.put("serverOwned", true);
        return map;
    }

    public HypothesisExperimentPlan withProbeAttempt(String probeAttemptId) {
        return new HypothesisExperimentPlan(
                schemaVersion, experimentPlanId, hypothesisId, scanId, planKind,
                entrypointRef, track, expectedSignals, counterSignals, stopCondition,
                maxAttempts, stageAttemptId, probeAttemptId);
    }

    public HypothesisExperimentPlan withStageAttempt(String stageAttemptId) {
        return new HypothesisExperimentPlan(
                schemaVersion, experimentPlanId, hypothesisId, scanId, planKind,
                entrypointRef, track, expectedSignals, counterSignals, stopCondition,
                maxAttempts, stageAttemptId, probeAttemptId);
    }
}
