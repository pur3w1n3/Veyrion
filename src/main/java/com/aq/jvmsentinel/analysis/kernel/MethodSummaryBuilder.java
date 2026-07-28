package com.aq.jvmsentinel.analysis.kernel;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bottom-up MethodSummary skeleton: seed primitive effects/sanitizers/guards from call edges,
 * then propagate custom effects to callers of summarized callees (wrapper pattern).
 */
public final class MethodSummaryBuilder {
    public static final int MAX_METHODS = 4_096;
    public static final int MAX_PROPAGATION_ROUNDS = 8;

    private MethodSummaryBuilder() {
    }

    public static Map<String, MethodSummary> build(
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.ResolvedCallEdge> resolvedEdges) {
        Map<String, MutableSummary> summaries = new LinkedHashMap<>();
        boolean methodBudgetHit = false;
        for (BytecodeFactIndex.MethodFact method : nullSafe(methods)) {
            if (summaries.size() >= MAX_METHODS) {
                methodBudgetHit = true;
                break;
            }
            String key = CfgBuilder.methodIdentity(method.owner(), method.name(), method.descriptor());
            MutableSummary summary = summaries.computeIfAbsent(key,
                    ignored -> new MutableSummary(method.owner(), method.name(), method.descriptor()));
            // Seed from the method's own identity (IR/sink/guard heuristics), not only callees.
            seedFromTarget(summary, method.owner(), method.name());
        }
        Map<String, Set<String>> calleesByCaller = new HashMap<>();
        for (BytecodeFactIndex.CallEdge edge : nullSafe(callEdges)) {
            String caller = CfgBuilder.methodIdentity(edge.callerOwner(), edge.callerName(), edge.callerDescriptor());
            MutableSummary summary = summaries.computeIfAbsent(caller,
                    ignored -> new MutableSummary(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
            seedFromTarget(summary, edge.targetOwner(), edge.targetName());
            String callee = CfgBuilder.methodIdentity(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
            calleesByCaller.computeIfAbsent(caller, ignored -> new LinkedHashSet<>()).add(callee);
            MutableSummary calleeSummary = summaries.computeIfAbsent(callee,
                    ignored -> new MutableSummary(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
            seedFromTarget(calleeSummary, edge.targetOwner(), edge.targetName());
            if (returnsValue(edge.targetDescriptor())) {
                // Conservative: any parameter may influence a value-returning callee result used by caller.
                for (int i = 0; i < parameterCount(edge.callerDescriptor()); i++) {
                    summary.returnTaintParams.add(i);
                }
            }
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : nullSafe(resolvedEdges)) {
            String caller = CfgBuilder.methodIdentity(edge.callerOwner(), edge.callerName(), edge.callerDescriptor());
            MutableSummary summary = summaries.computeIfAbsent(caller,
                    ignored -> new MutableSummary(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
            seedFromTarget(summary, edge.targetOwner(), edge.targetName());
            String callee = CfgBuilder.methodIdentity(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
            calleesByCaller.computeIfAbsent(caller, ignored -> new LinkedHashSet<>()).add(callee);
            MutableSummary calleeSummary = summaries.computeIfAbsent(callee,
                    ignored -> new MutableSummary(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
            seedFromTarget(calleeSummary, edge.targetOwner(), edge.targetName());
        }
        for (BytecodeFactIndex.MemberAccessFact access : nullSafe(memberAccesses)) {
            if (access.evidence() == null) continue;
            String ownerMethod = CfgBuilder.methodIdentity(access.evidence().className(),
                    access.evidence().methodName(), access.evidence().methodDescriptor());
            MutableSummary summary = summaries.computeIfAbsent(ownerMethod,
                    ignored -> new MutableSummary(access.evidence().className(),
                            access.evidence().methodName(), access.evidence().methodDescriptor()));
            String fieldKey = access.targetOwner() + "#" + access.targetName() + access.targetDescriptor();
            if (access.kind() == BytecodeFactIndex.AccessKind.FIELD_WRITE) {
                summary.fieldWrites.add(fieldKey);
                for (int i = 0; i < parameterCount(summary.descriptor); i++) {
                    summary.returnTaintParams.add(i);
                }
            } else if (access.kind() == BytecodeFactIndex.AccessKind.FIELD_READ) {
                summary.fieldReads.add(fieldKey);
            }
        }

        // Bottom-up: wrappers that call summarized effectful callees inherit custom effects.
        for (int round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
            boolean changed = false;
            for (Map.Entry<String, Set<String>> entry : calleesByCaller.entrySet()) {
                MutableSummary caller = summaries.get(entry.getKey());
                if (caller == null) continue;
                for (String calleeKey : entry.getValue()) {
                    MutableSummary callee = summaries.get(calleeKey);
                    if (callee == null || callee.effects.isEmpty()) continue;
                    for (String effect : callee.effects) {
                        String custom = effect.startsWith("CUSTOM:")
                                ? effect
                                : "CUSTOM:" + effect.replace("EFFECT:", "");
                        if (caller.effects.add(custom)) {
                            changed = true;
                        }
                    }
                    for (String sanitizer : callee.sanitizers) {
                        if (caller.sanitizers.add("VIA:" + sanitizer)) {
                            changed = true;
                        }
                    }
                }
            }
            if (!changed) break;
            if (round == MAX_PROPAGATION_ROUNDS - 1) {
                for (MutableSummary summary : summaries.values()) {
                    summary.stopReasons.add("SUMMARY_PROPAGATION_BUDGET");
                    summary.complete = false;
                }
            }
        }

        if (methodBudgetHit) {
            for (MutableSummary summary : summaries.values()) {
                summary.stopReasons.add("SUMMARY_METHOD_BUDGET");
                summary.complete = false;
            }
        }

        Map<String, MethodSummary> result = new LinkedHashMap<>();
        for (Map.Entry<String, MutableSummary> entry : summaries.entrySet()) {
            result.put(entry.getKey(), entry.getValue().freeze());
        }
        return Map.copyOf(result);
    }

    /** Convenience: summaries for methods that gained custom effects via callees. */
    public static List<MethodSummary> wrappersWithCustomEffects(Map<String, MethodSummary> summaries) {
        Objects.requireNonNull(summaries, "summaries");
        List<MethodSummary> wrappers = new ArrayList<>();
        for (MethodSummary summary : summaries.values()) {
            boolean hasCustom = summary.effects().stream().anyMatch(effect -> effect.startsWith("CUSTOM:"));
            boolean hasPrimitive = summary.effects().stream().anyMatch(effect -> effect.startsWith("EFFECT:"));
            if (hasCustom && !hasPrimitive) {
                wrappers.add(summary);
            }
        }
        return List.copyOf(wrappers);
    }

    private static void seedFromTarget(MutableSummary summary, String owner, String name) {
        PrimitiveEffectCatalog.match(owner, name).ifPresent(summary.effects::add);
        SanitizerCatalog.match(owner, name).ifPresent(summary.sanitizers::add);
        SanitizerCatalog.matchGuard(owner, name).ifPresent(summary.guards::add);
    }

    private static boolean returnsValue(String descriptor) {
        if (descriptor == null) return false;
        int close = descriptor.indexOf(')');
        return close >= 0 && close + 1 < descriptor.length() && descriptor.charAt(close + 1) != 'V';
    }

    private static int parameterCount(String descriptor) {
        if (descriptor == null || descriptor.length() < 2 || descriptor.charAt(0) != '(') return 0;
        int count = 0;
        int position = 1;
        while (position < descriptor.length() && descriptor.charAt(position) != ')') {
            while (descriptor.charAt(position) == '[') position++;
            if (descriptor.charAt(position++) == 'L') {
                position = descriptor.indexOf(';', position) + 1;
                if (position == 0) return count;
            }
            count++;
        }
        return count;
    }

    private static <T> List<T> nullSafe(List<T> values) {
        return values == null ? List.of() : values;
    }

    private static final class MutableSummary {
        private final String owner;
        private final String name;
        private final String descriptor;
        private final LinkedHashSet<String> effects = new LinkedHashSet<>();
        private final LinkedHashSet<String> guards = new LinkedHashSet<>();
        private final LinkedHashSet<String> sanitizers = new LinkedHashSet<>();
        private final LinkedHashSet<Integer> returnTaintParams = new LinkedHashSet<>();
        private final LinkedHashSet<String> fieldWrites = new LinkedHashSet<>();
        private final LinkedHashSet<String> fieldReads = new LinkedHashSet<>();
        private final List<String> stopReasons = new ArrayList<>();
        private boolean complete = true;

        private MutableSummary(String owner, String name, String descriptor) {
            this.owner = owner == null ? "" : owner;
            this.name = name == null ? "" : name;
            this.descriptor = descriptor == null ? "" : descriptor;
        }

        private MethodSummary freeze() {
            return new MethodSummary(owner, name, descriptor,
                    List.copyOf(effects), List.copyOf(guards), List.copyOf(sanitizers),
                    Set.copyOf(returnTaintParams), List.copyOf(fieldWrites), List.copyOf(fieldReads),
                    complete, List.copyOf(new LinkedHashSet<>(stopReasons)));
        }
    }
}
