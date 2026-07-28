package com.aq.jvmsentinel.analysis.kernel;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bounded field / return taint enhancement hooks over existing {@link BytecodeFactIndex.TaintPath}s.
 * Does not replace {@code InterproceduralTaintAnalyzer}; it annotates paths with FIELD/RETURN/SANITIZER steps.
 */
public final class FieldReturnTaintEnhancer {
    public static final int PATH_BUDGET = 2_048;
    public static final int STEP_BUDGET = 64;

    private FieldReturnTaintEnhancer() {
    }

    public record Enhancement(
            List<BytecodeFactIndex.TaintPath> enhancedPaths,
            List<String> fieldFlows,
            List<String> returnFlows,
            List<String> sanitizerHits,
            List<String> stopReasons) {
        public Enhancement {
            enhancedPaths = List.copyOf(enhancedPaths == null ? List.of() : enhancedPaths);
            fieldFlows = List.copyOf(fieldFlows == null ? List.of() : fieldFlows);
            returnFlows = List.copyOf(returnFlows == null ? List.of() : returnFlows);
            sanitizerHits = List.copyOf(sanitizerHits == null ? List.of() : sanitizerHits);
            stopReasons = List.copyOf(stopReasons == null ? List.of() : stopReasons);
        }
    }

    public static Enhancement enhance(
            List<BytecodeFactIndex.TaintPath> paths,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.CallEdge> callEdges) {
        Objects.requireNonNull(paths, "paths");
        Map<String, List<String>> fieldWritesByMethod = new HashMap<>();
        Map<String, List<String>> fieldReadsByMethod = new HashMap<>();
        for (BytecodeFactIndex.MemberAccessFact access : nullSafe(memberAccesses)) {
            if (access.evidence() == null) continue;
            String method = CfgBuilder.methodIdentity(access.evidence().className(),
                    access.evidence().methodName(), access.evidence().methodDescriptor());
            String fieldKey = access.targetOwner() + "#" + access.targetName() + access.targetDescriptor();
            if (access.kind() == BytecodeFactIndex.AccessKind.FIELD_WRITE) {
                fieldWritesByMethod.computeIfAbsent(method, ignored -> new ArrayList<>()).add(fieldKey);
            } else if (access.kind() == BytecodeFactIndex.AccessKind.FIELD_READ) {
                fieldReadsByMethod.computeIfAbsent(method, ignored -> new ArrayList<>()).add(fieldKey);
            }
        }
        Map<String, List<BytecodeFactIndex.CallEdge>> callsByMethod = new HashMap<>();
        for (BytecodeFactIndex.CallEdge edge : nullSafe(callEdges)) {
            String method = CfgBuilder.methodIdentity(edge.callerOwner(), edge.callerName(), edge.callerDescriptor());
            callsByMethod.computeIfAbsent(method, ignored -> new ArrayList<>()).add(edge);
        }

        List<BytecodeFactIndex.TaintPath> enhanced = new ArrayList<>();
        LinkedHashSet<String> fieldFlows = new LinkedHashSet<>();
        LinkedHashSet<String> returnFlows = new LinkedHashSet<>();
        LinkedHashSet<String> sanitizerHits = new LinkedHashSet<>();
        List<String> stopReasons = new ArrayList<>();
        int emitted = 0;
        for (BytecodeFactIndex.TaintPath path : paths) {
            if (emitted >= PATH_BUDGET) {
                stopReasons.add("FIELD_RETURN_PATH_BUDGET");
                break;
            }
            List<BytecodeFactIndex.TaintStep> steps = new ArrayList<>(path.steps());
            String sourceMethod = CfgBuilder.methodIdentity(path.sourceOwner(), path.sourceMethod(),
                    path.sourceDescriptor());
            for (String field : fieldWritesByMethod.getOrDefault(sourceMethod, List.of())) {
                if (steps.size() >= STEP_BUDGET) {
                    stopReasons.add("FIELD_RETURN_STEP_BUDGET");
                    break;
                }
                steps.add(new BytecodeFactIndex.TaintStep(
                        "FIELD_STORE", field, "FIELD",
                        "kernel:field-store:" + field,
                        "bounded field write in source method; aliasing is not proven"));
                fieldFlows.add(sourceMethod + "->" + field);
            }
            for (BytecodeFactIndex.CallEdge edge : callsByMethod.getOrDefault(sourceMethod, List.of())) {
                SanitizerCatalog.match(edge.targetOwner(), edge.targetName()).ifPresent(marker -> {
                    if (steps.size() < STEP_BUDGET) {
                        steps.add(new BytecodeFactIndex.TaintStep(
                                "SANITIZER", marker, "SANITIZER",
                                edge.evidence().stableKey(),
                                "sanitizer marker matched; neutralization is not proven"));
                        sanitizerHits.add(marker + "@" + edge.evidence().stableKey());
                    }
                });
                if (returnsValue(edge.targetDescriptor())) {
                    String flow = sourceMethod + "<-return-" + edge.targetOwner() + "#" + edge.targetName();
                    if (returnFlows.add(flow) && steps.size() < STEP_BUDGET) {
                        steps.add(new BytecodeFactIndex.TaintStep(
                                "RETURN_PROP", edge.targetOwner() + "#" + edge.targetName()
                                + edge.targetDescriptor(),
                                "RETURN", edge.evidence().stableKey(),
                                "bounded return-value propagation candidate from callee"));
                    }
                }
            }
            // Field-read bridge: if a later CALL step's method reads a field written by source method.
            Set<String> written = new HashSet<>(fieldWritesByMethod.getOrDefault(sourceMethod, List.of()));
            for (BytecodeFactIndex.TaintStep step : path.steps()) {
                if (!"CALL".equals(step.kind())) continue;
                String calleeHint = step.symbol();
                for (Map.Entry<String, List<String>> entry : fieldReadsByMethod.entrySet()) {
                    if (!calleeHint.contains(simpleName(entry.getKey()))) continue;
                    for (String field : entry.getValue()) {
                        if (!written.contains(field)) continue;
                        if (steps.size() >= STEP_BUDGET) break;
                        steps.add(new BytecodeFactIndex.TaintStep(
                                "FIELD_LOAD", field, "FIELD",
                                "kernel:field-load:" + field,
                                "bounded field read after prior write; object identity is not proven"));
                        fieldFlows.add(entry.getKey() + "<-" + field);
                    }
                }
            }
            enhanced.add(new BytecodeFactIndex.TaintPath(
                    path.id(), path.sourceOwner(), path.sourceMethod(), path.sourceDescriptor(),
                    path.sourceParameter(), path.sinkOwner(), path.sinkMethod(), path.sinkDescriptor(),
                    path.category(), steps, path.status()));
            emitted++;
        }
        return new Enhancement(enhanced, List.copyOf(fieldFlows), List.copyOf(returnFlows),
                List.copyOf(sanitizerHits), stopReasons);
    }

    private static boolean returnsValue(String descriptor) {
        if (descriptor == null) return false;
        int close = descriptor.indexOf(')');
        return close >= 0 && close + 1 < descriptor.length() && descriptor.charAt(close + 1) != 'V';
    }

    private static String simpleName(String methodKey) {
        int hash = methodKey.indexOf('#');
        if (hash < 0) return methodKey;
        String owner = methodKey.substring(0, hash);
        int slash = Math.max(owner.lastIndexOf('/'), owner.lastIndexOf('.'));
        return slash >= 0 ? owner.substring(slash + 1) : owner;
    }

    private static <T> List<T> nullSafe(List<T> values) {
        return values == null ? List.of() : values;
    }
}
