package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ObservationKind;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 将 PathRun-like fact 投影为统一 RuntimeObservation 并标记
 * 最小增量 detector subject（P1-06）。
 */
public final class RuntimeObservationProjector {
    private RuntimeObservationProjector() {
    }

    /**
     * 失败/空 projection：successfulProjection=false，lifecycle 不得变更。
     */
    public static RuntimeObservation emptyOrFailed(String hypothesisId,
                                                   ExperimentPlanKind planKind,
                                                   String reason) {
        String safeReason = reason == null || reason.isBlank() ? "EMPTY_OR_FAILED" : reason.trim();
        return new RuntimeObservation(
                "obs:failed:" + (hypothesisId == null ? "none" : hypothesisId) + ":" + safeReason,
                "",
                hypothesisId == null ? "" : hypothesisId,
                planKind,
                ObservationKind.UNKNOWN,
                safeReason.toUpperCase(Locale.ROOT),
                "UNKNOWN",
                false,
                List.of(),
                "RUNTIME_OBSERVED",
                List.of()
        );
    }

    public static RuntimeObservation fromPathRunProjection(
            String pathRunId,
            String hypothesisId,
            ExperimentPlanKind planKind,
            String outcomeClass,
            Boolean entryHit,
            Boolean effectHit,
            String signalHint,
            List<String> evidenceRefs,
            boolean successfulProjection) {
        Objects.requireNonNull(planKind, "planKind");
        if (!successfulProjection
                || pathRunId == null || pathRunId.isBlank()
                || evidenceRefs == null || evidenceRefs.isEmpty()) {
            return emptyOrFailed(hypothesisId, planKind, "EMPTY_OR_FAILED_PROJECTION");
        }

        ObservationKind kind = kindFor(planKind, entryHit, effectHit, signalHint);
        String signal = resolveSignal(planKind, outcomeClass, entryHit, effectHit, signalHint);
        List<ObservationKind> incremental = incrementalSubjects(planKind, kind, signalHint);

        return new RuntimeObservation(
                "obs:" + pathRunId,
                pathRunId.trim(),
                hypothesisId == null ? "" : hypothesisId.trim(),
                planKind,
                kind,
                signal,
                outcomeClass == null ? "COMPLETED" : outcomeClass.trim().toUpperCase(Locale.ROOT),
                true,
                List.copyOf(evidenceRefs),
                "RUNTIME_OBSERVED",
                incremental
        );
    }

    private static ObservationKind kindFor(ExperimentPlanKind planKind,
                                           Boolean entryHit,
                                           Boolean effectHit,
                                           String signalHint) {
        if (signalHint != null && signalHint.toUpperCase(Locale.ROOT).contains("BRANCH")) {
            return ObservationKind.BRANCH;
        }
        return switch (planKind) {
            case REACHABILITY -> Boolean.TRUE.equals(entryHit) ? ObservationKind.ENTRY : ObservationKind.EXCEPTION;
            case DATAFLOW_DIFF -> Boolean.TRUE.equals(effectHit) ? ObservationKind.EFFECT : ObservationKind.ENTRY;
            case GUARD_DIFF -> ObservationKind.GUARD;
            case STATE_SEQUENCE -> ObservationKind.STATE;
            case TYPESTATE_API -> ObservationKind.EFFECT;
            case CONCURRENCY_RESOURCE -> ObservationKind.DEPENDENCY;
        };
    }

    private static String resolveSignal(ExperimentPlanKind planKind,
                                        String outcomeClass,
                                        Boolean entryHit,
                                        Boolean effectHit,
                                        String signalHint) {
        if (signalHint != null && !signalHint.isBlank()) {
            return signalHint.trim().toUpperCase(Locale.ROOT);
        }
        String outcome = outcomeClass == null ? "" : outcomeClass.trim().toUpperCase(Locale.ROOT);
        // GUARD_DIFF 映射 AUTH_CHALLENGE → GUARD_DENY（counter）；其他 kind 保持 AUTH_CHALLENGE。
        if ("AUTH_CHALLENGE".equals(outcome) && planKind != ExperimentPlanKind.GUARD_DIFF) {
            return "AUTH_CHALLENGE";
        }
        if ("UNREACHED".equals(outcome) || "COLD_START".equals(outcome) || "PROBE_BUDGET".equals(outcome)
                || "UNKNOWN".equals(outcome) || "TRANSPORT_ERROR".equals(outcome)
                || "BUSINESS_TIMEOUT".equals(outcome) || "IDENTITY_UNAVAILABLE".equals(outcome)
                || "DEPENDENCY_MOCK_GAP".equals(outcome)) {
            return "UNREACHED";
        }
        return switch (planKind) {
            case REACHABILITY -> Boolean.TRUE.equals(entryHit) ? "ENTRY_HIT" : "UNREACHED";
            case DATAFLOW_DIFF -> Boolean.TRUE.equals(effectHit) ? "EFFECT_STRUCTURE_DIFF" : "PARAMETERIZED_BLOCK";
            case GUARD_DIFF -> "AUTH_CHALLENGE".equals(outcome) ? "GUARD_DENY" : "GUARD_BYPASS";
            case STATE_SEQUENCE -> "STATE_TRANSITION";
            case TYPESTATE_API -> "TYPESTATE_MISUSE";
            case CONCURRENCY_RESOURCE -> "RACE_WINDOW";
        };
    }

    private static List<ObservationKind> incrementalSubjects(ExperimentPlanKind planKind,
                                                             ObservationKind primary,
                                                             String signalHint) {
        List<ObservationKind> subjects = new ArrayList<>();
        subjects.add(primary);
        if (signalHint != null && signalHint.toUpperCase(Locale.ROOT).contains("BRANCH")) {
            subjects.add(ObservationKind.BRANCH);
        }
        switch (planKind) {
            case DATAFLOW_DIFF -> {
                subjects.add(ObservationKind.EFFECT);
                subjects.add(ObservationKind.ENTRY);
            }
            case GUARD_DIFF -> {
                subjects.add(ObservationKind.GUARD);
                subjects.add(ObservationKind.ENTRY);
            }
            case STATE_SEQUENCE -> subjects.add(ObservationKind.STATE);
            case TYPESTATE_API -> subjects.add(ObservationKind.EFFECT);
            case CONCURRENCY_RESOURCE -> {
                subjects.add(ObservationKind.DEPENDENCY);
                subjects.add(ObservationKind.STATE);
            }
            case REACHABILITY -> subjects.add(ObservationKind.ENTRY);
        }
        return List.copyOf(subjects.stream().distinct().toList());
    }
}
