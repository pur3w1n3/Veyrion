package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Compare a compiled TracePlan (static expectations) against an observed PathTrace.
 * Used for PATH/TRIAGE prompt injection and probe prioritization — never elevates verification.
 */
public final class TracePlanObservationDiff {
    private TracePlanObservationDiff() {
    }

    public record Diff(
            String tracePlanId,
            String pathRunId,
            String entryRef,
            List<String> expectedGuardsMissing,
            List<String> expectedEffectsMissing,
            List<String> expectedHopsMissing,
            List<String> observedEffectsExtra,
            List<String> observedGuards,
            List<String> observedEffects,
            List<String> observedHops,
            boolean entryObserved,
            String exitReason,
            String lastBusinessHop
    ) {
        public Diff {
            expectedGuardsMissing = List.copyOf(expectedGuardsMissing == null ? List.of() : expectedGuardsMissing);
            expectedEffectsMissing = List.copyOf(expectedEffectsMissing == null ? List.of() : expectedEffectsMissing);
            expectedHopsMissing = List.copyOf(expectedHopsMissing == null ? List.of() : expectedHopsMissing);
            observedEffectsExtra = List.copyOf(observedEffectsExtra == null ? List.of() : observedEffectsExtra);
            observedGuards = List.copyOf(observedGuards == null ? List.of() : observedGuards);
            observedEffects = List.copyOf(observedEffects == null ? List.of() : observedEffects);
            observedHops = List.copyOf(observedHops == null ? List.of() : observedHops);
            exitReason = exitReason == null ? "" : exitReason;
            lastBusinessHop = lastBusinessHop == null ? "" : lastBusinessHop;
        }

        public boolean hasGaps() {
            return !expectedGuardsMissing.isEmpty()
                    || !expectedEffectsMissing.isEmpty()
                    || !expectedHopsMissing.isEmpty();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("tracePlanId", tracePlanId);
            map.put("pathRunId", pathRunId);
            map.put("entryRef", entryRef);
            map.put("entryObserved", entryObserved);
            map.put("exitReason", exitReason);
            map.put("lastBusinessHop", lastBusinessHop);
            map.put("expectedGuardsMissing", expectedGuardsMissing);
            map.put("expectedEffectsMissing", expectedEffectsMissing);
            map.put("expectedHopsMissing", expectedHopsMissing);
            map.put("observedEffectsExtra", observedEffectsExtra);
            map.put("observedGuards", observedGuards);
            map.put("observedEffects", observedEffects);
            map.put("observedHopsSample", observedHops.size() > 12
                    ? observedHops.subList(0, 12) : observedHops);
            map.put("hasGaps", hasGaps());
            return map;
        }
    }

    public static Diff diff(TracePlan plan, PathTrace trace) {
        Objects.requireNonNull(plan, "plan");
        List<String> observedGuards = new ArrayList<>();
        List<String> observedEffects = new ArrayList<>();
        List<String> observedHops = new ArrayList<>();
        boolean entryHit = false;
        String exit = "";
        String lastHop = "";
        String pathRunId = "";
        if (trace != null) {
            pathRunId = trace.pathRunId() == null ? "" : trace.pathRunId();
            exit = trace.exitReason() == null ? "" : trace.exitReason().name();
            lastHop = trace.lastBusinessHop() == null ? "" : trace.lastBusinessHop();
            if (trace.effectRefs() != null) {
                observedEffects.addAll(trace.effectRefs());
            }
            if (trace.events() != null) {
                for (TraceEvent event : trace.events()) {
                    if (event == null || event.kind() == null) {
                        continue;
                    }
                    TraceEventKind kind = event.kind();
                    String subject = !event.subjectRef().isBlank()
                            ? event.subjectRef()
                            : (event.summary().isBlank() ? kind.name() : event.summary());
                    if (kind == TraceEventKind.ENTRY_HIT) {
                        entryHit = true;
                    }
                    if (kind == TraceEventKind.GUARD_DECISION) {
                        observedGuards.add(subject);
                    }
                    if (kind == TraceEventKind.EFFECT_TRIGGERED) {
                        observedEffects.add(subject);
                    }
                    if (kind == TraceEventKind.METHOD_HOP || kind == TraceEventKind.DEPENDENCY_CALL) {
                        observedHops.add(subject);
                    }
                }
            }
            if (!lastHop.isBlank() && !observedHops.contains(lastHop)) {
                observedHops.add(lastHop);
            }
        }
        return new Diff(
                plan.tracePlanId(),
                pathRunId,
                plan.entryRef(),
                missing(plan.expectedGuardRefs(), observedGuards),
                missing(plan.expectedEffectRefs(), observedEffects),
                missing(plan.expectedHops(), observedHops),
                extras(plan.expectedEffectRefs(), observedEffects),
                observedGuards,
                observedEffects,
                observedHops,
                entryHit,
                exit,
                lastHop);
    }

    /**
     * Pair each TracePlan with the best PathTrace for its entry (prefer matching
     * {@code tracePlanId}, else any trace on same entryRef). Plans without traces still emit
     * a gap row so PATH/TRIAGE can prioritize unobserved expected effects.
     */
    public static List<Diff> diffAll(List<TracePlan> plans, List<PathTrace> traces) {
        if (plans == null || plans.isEmpty()) {
            return List.of();
        }
        Map<String, PathTrace> byPlanId = new LinkedHashMap<>();
        Map<String, PathTrace> byEntry = new LinkedHashMap<>();
        if (traces != null) {
            for (PathTrace trace : traces) {
                if (trace == null) {
                    continue;
                }
                if (trace.tracePlanId() != null && !trace.tracePlanId().isBlank()) {
                    byPlanId.putIfAbsent(trace.tracePlanId(), trace);
                }
                if (trace.entryRef() != null && !trace.entryRef().isBlank()) {
                    byEntry.putIfAbsent(trace.entryRef(), trace);
                }
            }
        }
        List<Diff> out = new ArrayList<>();
        for (TracePlan plan : plans) {
            if (plan == null) {
                continue;
            }
            PathTrace matched = byPlanId.get(plan.tracePlanId());
            if (matched == null) {
                matched = byEntry.get(plan.entryRef());
            }
            out.add(diff(plan, matched));
        }
        return List.copyOf(out);
    }

    public static String formatForPrompt(List<Diff> diffs, boolean english, int maxRows) {
        int limit = Math.max(1, Math.min(maxRows <= 0 ? 16 : maxRows, 48));
        StringBuilder block = new StringBuilder();
        if (english) {
            block.append("TRACE_PLAN_VS_ACTUAL (plan expectations vs PathTrace; gaps are probe priorities; ")
                    .append("FORCED gaps ≠ VERIFIED):\n");
        } else {
            block.append("TRACE_PLAN_VS_ACTUAL（计划预期 vs 实际 PathTrace；缺口优先探针；")
                    .append("FORCED 缺口≠已验证）：\n");
        }
        if (diffs == null || diffs.isEmpty()) {
            block.append(english
                    ? "- No TracePlan/PathTrace pairs yet; compile TracePlan from static IR before claiming coverage.\n"
                    : "- 尚无 TracePlan/PathTrace 对照；先据静态 IR 编译 TracePlan，再谈覆盖。\n");
            return block.toString();
        }
        int emitted = 0;
        int gapCount = 0;
        for (Diff diff : diffs) {
            if (diff == null) {
                continue;
            }
            if (diff.hasGaps()) {
                gapCount++;
            }
            if (emitted >= limit) {
                continue;
            }
            // Prefer emitting gap rows first by sorting callers; here emit in order.
            block.append("- entry=").append(diff.entryRef())
                    .append(" plan=").append(diff.tracePlanId())
                    .append(" pathRun=").append(diff.pathRunId().isBlank() ? "(none)" : diff.pathRunId())
                    .append(" entryHit=").append(diff.entryObserved())
                    .append(" exit=").append(diff.exitReason());
            if (!diff.expectedEffectsMissing().isEmpty()) {
                block.append(" missingEffects=").append(cap(diff.expectedEffectsMissing(), 4));
            }
            if (!diff.expectedGuardsMissing().isEmpty()) {
                block.append(" missingGuards=").append(cap(diff.expectedGuardsMissing(), 4));
            }
            if (!diff.expectedHopsMissing().isEmpty()) {
                block.append(" missingHops=").append(cap(diff.expectedHopsMissing(), 4));
            }
            if (!diff.observedEffects().isEmpty()) {
                block.append(" observedEffects=").append(cap(diff.observedEffects(), 4));
            }
            block.append('\n');
            emitted++;
        }
        if (diffs.size() > limit) {
            block.append(english
                    ? "- …" + (diffs.size() - limit) + " more pairs omitted; deepen with facts_search kind=PATH_TRACE.\n"
                    : "- …另有 " + (diffs.size() - limit) + " 对未内联；用 facts_search kind=PATH_TRACE 深挖。\n");
        }
        block.append(english
                ? "- gapPairs=" + gapCount + "; prefer sandbox_probe on entries with missingEffects.\n"
                : "- 缺口对数=" + gapCount + "；优先对 missingEffects 的入口 sandbox_probe。\n");
        return block.toString();
    }

    /** Entry ids whose TracePlan still misses expected effects after all traces. */
    public static List<String> entriesWithMissingEffects(List<Diff> diffs) {
        Set<String> ids = new LinkedHashSet<>();
        if (diffs == null) {
            return List.of();
        }
        for (Diff diff : diffs) {
            if (diff != null && !diff.expectedEffectsMissing().isEmpty()
                    && diff.entryRef() != null && !diff.entryRef().isBlank()) {
                ids.add(diff.entryRef());
            }
        }
        return List.copyOf(ids);
    }

    /** Sort diffs so gap rows (especially missing effects) appear first. */
    public static List<Diff> prioritizeGaps(List<Diff> diffs) {
        if (diffs == null || diffs.isEmpty()) {
            return List.of();
        }
        List<Diff> sorted = new ArrayList<>(diffs);
        sorted.sort((a, b) -> Integer.compare(gapScore(b), gapScore(a)));
        return List.copyOf(sorted);
    }

    private static int gapScore(Diff diff) {
        if (diff == null) {
            return 0;
        }
        int score = 0;
        score += diff.expectedEffectsMissing().size() * 10;
        score += diff.expectedGuardsMissing().size() * 3;
        score += diff.expectedHopsMissing().size();
        if (!diff.entryObserved() && !diff.expectedEffectsMissing().isEmpty()) {
            score += 5;
        }
        return score;
    }

    private static List<String> missing(List<String> expected, List<String> observed) {
        if (expected == null || expected.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String exp : expected) {
            if (exp == null || exp.isBlank()) {
                continue;
            }
            if (!containsLoose(observed, exp)) {
                out.add(exp);
            }
        }
        return out;
    }

    private static List<String> extras(List<String> expected, List<String> observed) {
        if (observed == null || observed.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String obs : observed) {
            if (obs == null || obs.isBlank()) {
                continue;
            }
            if (!containsLoose(expected, obs)) {
                out.add(obs);
            }
        }
        return out;
    }

    private static boolean containsLoose(List<String> haystack, String needle) {
        if (haystack == null || needle == null || needle.isBlank()) {
            return false;
        }
        String n = needle.toLowerCase(Locale.ROOT);
        for (String item : haystack) {
            if (item == null || item.isBlank()) {
                continue;
            }
            String h = item.toLowerCase(Locale.ROOT);
            if (h.contains(n) || n.contains(h)) {
                return true;
            }
            String nBare = n.replace("effect:", "").replace("sink:", "").replace("guard:", "")
                    .replace("taint:", "");
            String hBare = h.replace("effect:", "").replace("sink:", "").replace("guard:", "")
                    .replace("taint:", "");
            if (!nBare.isBlank() && (hBare.contains(nBare) || nBare.contains(hBare))) {
                return true;
            }
        }
        return false;
    }

    private static List<String> cap(List<String> values, int max) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.size() <= max ? values : values.subList(0, max);
    }
}
