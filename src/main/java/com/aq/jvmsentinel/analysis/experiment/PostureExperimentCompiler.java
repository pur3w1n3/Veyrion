package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.experiment.ExperimentSignal;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * P0-21：将 entry × 0-n parameter × posture 编译为服务端 owned experiment plan。
 */
public final class PostureExperimentCompiler {
    public static final String PRODUCER = "posture-experiment-compiler/0.1";

    private PostureExperimentCompiler() {
    }

    public record CompiledPostureExperiment(
            String experimentPlanId,
            String tracePlanId,
            String worldPackId,
            String entryRef,
            String method,
            String route,
            RuntimePosture posture,
            IdentityTrack track,
            List<EntryParameterExperimentCompiler.CompiledParameter> parameters,
            String query,
            String body,
            String emptyInputRationale,
            List<ExperimentSignal> expectedSignals,
            List<ExperimentSignal> counterSignals,
            String stopCondition
    ) {
        public CompiledPostureExperiment {
            Objects.requireNonNull(experimentPlanId, "experimentPlanId");
            if (experimentPlanId.isBlank()) {
                throw new IllegalArgumentException("experimentPlanId must not be blank");
            }
            Objects.requireNonNull(tracePlanId, "tracePlanId");
            Objects.requireNonNull(worldPackId, "worldPackId");
            Objects.requireNonNull(posture, "posture");
            parameters = List.copyOf(parameters == null ? List.of() : parameters);
            expectedSignals = List.copyOf(expectedSignals == null ? List.of() : expectedSignals);
            counterSignals = List.copyOf(counterSignals == null ? List.of() : counterSignals);
            query = query == null ? "" : query;
            body = body == null ? "" : body;
            emptyInputRationale = emptyInputRationale == null ? "" : emptyInputRationale;
            stopCondition = stopCondition == null || stopCondition.isBlank()
                    ? "BUDGET_OR_EXIT_SIGNAL" : stopCondition.trim();
            track = track == null ? wireTrack(posture) : track;
        }

        public Map<String, Object> toWireMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("experimentPlanId", experimentPlanId);
            map.put("tracePlanId", tracePlanId);
            map.put("worldPackId", worldPackId);
            map.put("entryRef", entryRef);
            map.put("method", method);
            map.put("route", route);
            map.put("posture", posture.toMap());
            map.put("postureKind", posture.postureKind().name());
            map.put("track", track.name());
            map.put("query", query);
            map.put("body", body);
            map.put("emptyInputRationale", emptyInputRationale);
            map.put("stopCondition", stopCondition);
            map.put("producer", PRODUCER);
            map.put("expectedSignals", expectedSignals.stream().map(ExperimentSignal::code).toList());
            map.put("counterSignals", counterSignals.stream().map(ExperimentSignal::code).toList());
            return map;
        }

        private static IdentityTrack wireTrack(RuntimePosture posture) {
            return switch (posture.identityTrackWire().toUpperCase(Locale.ROOT)) {
                case "ADMIN" -> IdentityTrack.ADMIN;
                case "USER" -> IdentityTrack.USER;
                case "BYPASS_CANDIDATE" -> IdentityTrack.BYPASS_CANDIDATE;
                default -> IdentityTrack.UNAUTH;
            };
        }
    }

    public static List<CompiledPostureExperiment> compile(
            ApiDtos.EntryDto entry,
            String scanId,
            List<String> callEdgeHints,
            List<String> effectHints,
            List<String> guardHints,
            List<String> unresolvedHints,
            List<String> bypassCandidates,
            int maxPlans) {
        Objects.requireNonNull(entry, "entry");
        TracePlan tracePlan = TracePlanCompiler.compile(
                entry, callEdgeHints, effectHints, guardHints, unresolvedHints);
        WorldPackManifestPair worldPacks = worldPacksFor(scanId);
        List<EntryParameterExperimentCompiler.CompiledExperiment> paramPlans =
                EntryParameterExperimentCompiler.compile(List.of(entry), List.of(), maxPlans);
        EntryParameterExperimentCompiler.CompiledExperiment base = paramPlans.isEmpty()
                ? emptyParamPlan(entry) : paramPlans.get(0);
        boolean bypass = bypassCandidates != null && bypassCandidates.stream()
                .anyMatch(ref -> ref != null && (ref.contains(entry.id()) || ref.contains(entry.route())));
        List<RuntimePosture> postures = RuntimePostureOrchestrator.planDefaultPostures(guardHints, bypass);
        int limit = Math.max(1, Math.min(maxPlans <= 0 ? 64 : maxPlans, 256));
        List<CompiledPostureExperiment> out = new ArrayList<>();
        for (RuntimePosture posture : postures) {
            if (out.size() >= limit) {
                break;
            }
            out.add(compileOne(entry, tracePlan, worldPacks, base, posture));
        }
        return List.copyOf(out);
    }

    public static List<CompiledPostureExperiment> compileAll(
            List<ApiDtos.EntryDto> entries,
            String scanId,
            List<String> callEdgeHints,
            List<String> effectHints,
            List<String> guardHints,
            List<String> unresolvedHints,
            List<String> bypassCandidates,
            int maxPlans) {
        int limit = Math.max(1, Math.min(maxPlans <= 0 ? 64 : maxPlans, 256));
        List<ApiDtos.EntryDto> entryList = entries == null ? List.of() : entries;
        List<CompiledPostureExperiment> out = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entryList) {
            if (entry == null || entry.route() == null || entry.route().isBlank()) {
                continue;
            }
            for (CompiledPostureExperiment plan : compile(
                    entry, scanId, callEdgeHints, effectHints, guardHints, unresolvedHints,
                    bypassCandidates, limit - out.size())) {
                if (out.size() >= limit) {
                    return List.copyOf(out);
                }
                out.add(plan);
            }
        }
        return List.copyOf(out);
    }

    private static CompiledPostureExperiment compileOne(
            ApiDtos.EntryDto entry,
            TracePlan tracePlan,
            WorldPackManifestPair worldPacks,
            EntryParameterExperimentCompiler.CompiledExperiment base,
            RuntimePosture posture) {
        String worldPackId = posture.postureKind() == RuntimePostureKind.FORCED_REACHABILITY
                ? worldPacks.mockContinueId()
                : worldPacks.observeFailId();
        String planId = boundedPlanId(entry.id(), posture.postureKind());
        return new CompiledPostureExperiment(
                planId,
                tracePlan.tracePlanId(),
                worldPackId,
                entry.id(),
                tracePlan.method(),
                tracePlan.route(),
                posture,
                wireTrack(posture),
                base.parameters(),
                base.query(),
                base.body(),
                base.emptyInputRationale().isBlank()
                        ? tracePlan.emptyInputRationale() : base.emptyInputRationale(),
                expectedFor(posture),
                counterFor(posture),
                stopConditionFor(posture));
    }

    private static IdentityTrack wireTrack(RuntimePosture posture) {
        return switch (posture.identityTrackWire().toUpperCase(Locale.ROOT)) {
            case "ADMIN" -> IdentityTrack.ADMIN;
            case "USER" -> IdentityTrack.USER;
            case "BYPASS_CANDIDATE" -> IdentityTrack.BYPASS_CANDIDATE;
            default -> IdentityTrack.UNAUTH;
        };
    }

    private static List<ExperimentSignal> expectedFor(RuntimePosture posture) {
        return switch (posture.postureKind()) {
            case UNAUTH -> List.of(
                    ExperimentSignal.of("ENTRY_HIT"),
                    ExperimentSignal.of("AUTH_CHALLENGE"));
            case COVERAGE_POSTURE -> List.of(
                    ExperimentSignal.of("ENTRY_HIT"),
                    ExperimentSignal.of("EFFECT_HIT"),
                    ExperimentSignal.of("PARAMETER_BOUND"));
            case FORCED_REACHABILITY -> List.of(
                    ExperimentSignal.of("FORCED_PAST_GUARD"),
                    ExperimentSignal.of("EFFECT_HIT"),
                    ExperimentSignal.of("METHOD_HOP"));
            case BYPASS -> List.of(
                    ExperimentSignal.of("GUARD_BYPASS"),
                    ExperimentSignal.of("SAME_EFFECT_DIFF_IDENTITY"));
        };
    }

    private static List<ExperimentSignal> counterFor(RuntimePosture posture) {
        return switch (posture.postureKind()) {
            case UNAUTH -> List.of(
                    ExperimentSignal.of("EFFECT_HIT"),
                    ExperimentSignal.of("FORCED_PAST_GUARD"));
            case COVERAGE_POSTURE -> List.of(
                    ExperimentSignal.of("AUTH_POSTURE_GAP"),
                    ExperimentSignal.of("IDENTITY_UNAVAILABLE"));
            case FORCED_REACHABILITY -> List.of(
                    ExperimentSignal.of("GUARD_BLOCKED"),
                    ExperimentSignal.of("TRACE_TRUNCATED"));
            case BYPASS -> List.of(
                    ExperimentSignal.of("GUARD_DENY"),
                    ExperimentSignal.of("IDENTITY_UNAVAILABLE"));
        };
    }

    private static String stopConditionFor(RuntimePosture posture) {
        return switch (posture.postureKind()) {
            case UNAUTH -> "AUTH_CHALLENGE_OR_BUDGET";
            case COVERAGE_POSTURE -> "EFFECT_OR_DEPENDENCY_EXIT";
            case FORCED_REACHABILITY -> "DEEPEST_PATH_OR_DEPENDENCY_EXIT";
            case BYPASS -> "GUARD_DECISION_OR_BUDGET";
        };
    }

    private static EntryParameterExperimentCompiler.CompiledExperiment emptyParamPlan(ApiDtos.EntryDto entry) {
        String method = entry.method() == null || entry.method().isBlank()
                ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        return new EntryParameterExperimentCompiler.CompiledExperiment(
                "plan:entry:" + entry.id(),
                entry.id(),
                method,
                entry.route(),
                IdentityTrack.UNAUTH,
                com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind.REACHABILITY,
                List.of(),
                "",
                "",
                "Empty input legal for posture compilation.",
                List.of(),
                List.of(),
                "EXECUTABLE",
                "");
    }

    private static WorldPackManifestPair worldPacksFor(String scanId) {
        var mock = WorldPackPlanner.planMockContinue(scanId);
        var observe = WorldPackPlanner.planObserveFail(scanId, List.of());
        return new WorldPackManifestPair(mock.worldPackId(), observe.worldPackId());
    }

    /**
     * 说明：ProbeTarget.experimentPlanId 须匹配 {@code [A-Za-z0-9_.:/-]{1,128}}。
     * Entry id 可为长 route key — 对 overflow hash 而非 registration 失败。
     */
    static String boundedPlanId(String entryId, RuntimePostureKind kind) {
        String posture = kind == null ? "unauth" : kind.name().toLowerCase(Locale.ROOT);
        String safeEntry = (entryId == null ? "entry" : entryId.trim())
                .replaceAll("[^A-Za-z0-9_.:/-]", "_");
        String prefix = "plan:posture:";
        String suffix = ":" + posture;
        int budget = 128 - prefix.length() - suffix.length();
        if (budget < 8) {
            budget = 8;
        }
        if (safeEntry.length() <= budget) {
            return prefix + safeEntry + suffix;
        }
        String hash = Integer.toHexString(safeEntry.hashCode());
        int keep = Math.max(4, budget - hash.length() - 1);
        return prefix + safeEntry.substring(0, keep) + "-" + hash + suffix;
    }

    private record WorldPackManifestPair(String mockContinueId, String observeFailId) {
    }
}
