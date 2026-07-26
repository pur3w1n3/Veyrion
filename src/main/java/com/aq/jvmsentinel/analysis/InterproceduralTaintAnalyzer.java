package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Artifact-local CHA and bounded parameter-origin propagation. */
final class InterproceduralTaintAnalyzer {
    static final int CALL_GRAPH_EDGE_BUDGET = 200_000;
    static final int TAINT_STATE_BUDGET = 50_000;
    private static final int CALL_GRAPH_RESOLUTION_BUDGET = 1_000_000;
    private static final int PATH_BUDGET = 20_000;
    private static final int CALL_DEPTH_BUDGET = 64;

    Result analyze(List<ClassMetadata> metadata) {
        Map<MethodId, BytecodeFactIndex.MethodFact> methods = new LinkedHashMap<>();
        Map<String, BytecodeFactIndex.ClassFact> classes = new LinkedHashMap<>();
        Map<MethodId, ClassMetadata.MethodFlowFact> flows = new LinkedHashMap<>();
        List<BytecodeFactIndex.CallEdge> symbolic = new ArrayList<>();
        for (ClassMetadata item : metadata) {
            if (item.classFact() != null) classes.put(item.className(), item.classFact());
            for (BytecodeFactIndex.MethodFact method : item.methodFacts()) {
                methods.put(new MethodId(method.owner(), method.name(), method.descriptor()), method);
            }
            for (ClassMetadata.MethodFlowFact flow : item.methodFlows()) {
                flows.put(new MethodId(flow.owner(), flow.name(), flow.descriptor()), flow);
            }
            symbolic.addAll(item.callEdges());
        }

        List<String> stopReasons = new ArrayList<>();
        List<BytecodeFactIndex.ResolvedCallEdge> graph = resolveGraph(symbolic, methods, classes, stopReasons);
        Map<String, List<BytecodeFactIndex.ResolvedCallEdge>> targetsByCall = new HashMap<>();
        for (BytecodeFactIndex.ResolvedCallEdge edge : graph) {
            targetsByCall.computeIfAbsent(edge.evidence().stableKey(), ignored -> new ArrayList<>()).add(edge);
        }

        ArrayDeque<State> queue = new ArrayDeque<>();
        for (ClassMetadata item : metadata) {
            if (!isController(item)) continue;
            for (ClassMetadata.MethodMetadata method : item.methods()) {
                if (!isMapping(method.annotations())) continue;
                for (int parameter = 0; parameter < method.parameters().size(); parameter++) {
                    MethodId source = new MethodId(item.className(), method.name(), method.descriptor());
                    BytecodeFactIndex.TaintStep sourceStep = new BytecodeFactIndex.TaintStep(
                            "SOURCE", source.display() + ":parameter-" + parameter, "SOURCE",
                            "classfile-annotation:" + source.display(),
                            "mapped entry parameter is a static source candidate; runtime control is not proven");
                    queue.addLast(new State(source, parameter, source, parameter, 0, List.of(sourceStep)));
                }
            }
        }

        List<BytecodeFactIndex.TaintPath> paths = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        int states = 0;
        boolean taintBudgetStopped = false;
        while (!queue.isEmpty()) {
            if (++states > TAINT_STATE_BUDGET) {
                stopReasons.add("TAINT_STATE_BUDGET_EXHAUSTED");
                taintBudgetStopped = true;
                break;
            }
            State state = queue.removeFirst();
            String visitKey = state.source.display() + ":" + state.sourceParameter + "->"
                    + state.method.display() + ":" + state.parameter;
            if (!visited.add(visitKey)) continue;
            ClassMetadata.MethodFlowFact flow = flows.get(state.method);
            if (flow == null) continue;
            if (!flow.complete() && !stopReasons.contains("METHOD_FLOW_PARTIAL")) {
                stopReasons.add("METHOD_FLOW_PARTIAL");
            }
            List<BytecodeFactIndex.TaintStep> prefix = new ArrayList<>(state.steps);
            for (ClassMetadata.InvocationFlowFact invocation : flow.invocations()) {
                boolean receiverTainted = invocation.receiverParameterOrigins().contains(state.parameter);
                List<Integer> taintedArguments = new ArrayList<>();
                for (int i = 0; i < invocation.argumentParameterOrigins().size(); i++) {
                    if (invocation.argumentParameterOrigins().get(i).contains(state.parameter)) {
                        taintedArguments.add(i);
                    }
                }
                if (!receiverTainted && taintedArguments.isEmpty()) continue;

                BytecodeFactIndex.CallEdge symbolicEdge = invocation.edge();
                JvmSinkSignatures.Match sink = JvmSinkSignatures.match(symbolicEdge);
                if (sink != null && paths.size() < PATH_BUDGET) {
                    List<BytecodeFactIndex.TaintStep> steps = new ArrayList<>(prefix);
                    steps.add(step("SINK", symbolicEdge, "owner+method+descriptor sink rule " + sink.ruleId()));
                    String id = "taint-" + (paths.size() + 1) + "-"
                            + Integer.toUnsignedString((state.source.display() + symbolicEdge.evidence().stableKey()
                            + state.sourceParameter).hashCode(), 36);
                    paths.add(new BytecodeFactIndex.TaintPath(id, state.source.owner, state.source.name,
                            state.source.descriptor, state.sourceParameter, symbolicEdge.targetOwner(),
                            symbolicEdge.targetName(), symbolicEdge.targetDescriptor(), sink.category(),
                            steps, "STATIC_INFERRED"));
                }

                List<BytecodeFactIndex.ResolvedCallEdge> targets = targetsByCall.getOrDefault(
                        symbolicEdge.evidence().stableKey(), List.of());
                boolean hasArtifactTarget = targets.stream()
                        .anyMatch(edge -> edge.kind() != BytecodeFactIndex.EdgeKind.UNRESOLVED);
                if (!hasArtifactTarget && sink == null && returnsValue(symbolicEdge.targetDescriptor())) {
                    prefix.add(step("TRANSFORM", symbolicEdge,
                            "tainted argument reaches an unresolved value-returning call; return propagation is conservative"));
                }
                for (BytecodeFactIndex.ResolvedCallEdge target : targets) {
                    if (target.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED) continue;
                    MethodId callee = new MethodId(target.targetOwner(), target.targetName(), target.targetDescriptor());
                    for (int argument : taintedArguments) {
                        if (argument >= parameterCount(target.targetDescriptor())) continue;
                        if (state.callDepth >= CALL_DEPTH_BUDGET) {
                            if (!stopReasons.contains("TAINT_CALL_DEPTH_BUDGET_EXHAUSTED")) {
                                stopReasons.add("TAINT_CALL_DEPTH_BUDGET_EXHAUSTED");
                            }
                            continue;
                        }
                        if (queue.size() + visited.size() >= TAINT_STATE_BUDGET) {
                            if (!stopReasons.contains("TAINT_STATE_BUDGET_EXHAUSTED")) {
                                stopReasons.add("TAINT_STATE_BUDGET_EXHAUSTED");
                            }
                            taintBudgetStopped = true;
                            continue;
                        }
                        List<BytecodeFactIndex.TaintStep> steps = new ArrayList<>(prefix);
                        steps.add(new BytecodeFactIndex.TaintStep("CALL", callee.display(), target.kind().name(),
                                target.evidence().stableKey(),
                                "taint passed through argument " + argument + "; runtime dispatch is not proven"));
                        queue.addLast(new State(state.source, state.sourceParameter, callee, argument,
                                state.callDepth + 1, steps));
                    }
                }
            }
        }
        if (paths.size() >= PATH_BUDGET) stopReasons.add("TAINT_PATH_BUDGET_EXHAUSTED");
        boolean graphBudgetStopped = stopReasons.stream().anyMatch(reason -> reason.startsWith("CALL_GRAPH_"));
        boolean complete = !graphBudgetStopped && !taintBudgetStopped
                && !stopReasons.contains("TAINT_PATH_BUDGET_EXHAUSTED")
                && !stopReasons.contains("METHOD_FLOW_PARTIAL")
                && !stopReasons.contains("TAINT_CALL_DEPTH_BUDGET_EXHAUSTED");
        BytecodeFactIndex.AnalysisCoverage coverage = new BytecodeFactIndex.AnalysisCoverage(
                CALL_GRAPH_EDGE_BUDGET, TAINT_STATE_BUDGET, graph.size(), Math.min(states, TAINT_STATE_BUDGET),
                complete, List.copyOf(new LinkedHashSet<>(stopReasons)));
        return new Result(graph, paths, coverage);
    }

    private static List<BytecodeFactIndex.ResolvedCallEdge> resolveGraph(
            List<BytecodeFactIndex.CallEdge> symbolic,
            Map<MethodId, BytecodeFactIndex.MethodFact> methods,
            Map<String, BytecodeFactIndex.ClassFact> classes,
            List<String> stopReasons) {
        List<BytecodeFactIndex.ResolvedCallEdge> result = new ArrayList<>();
        Set<String> dedupe = new HashSet<>();
        int resolutionChecks = 0;
        for (BytecodeFactIndex.CallEdge edge : symbolic) {
            List<MethodId> targets = new ArrayList<>();
            BytecodeFactIndex.EdgeKind kind;
            if (edge.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED) {
                kind = BytecodeFactIndex.EdgeKind.UNRESOLVED;
            } else if (edge.kind() == BytecodeFactIndex.EdgeKind.DIRECT) {
                MethodId exact = new MethodId(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
                if (methods.containsKey(exact)) targets.add(exact);
                kind = targets.isEmpty() ? BytecodeFactIndex.EdgeKind.UNRESOLVED : BytecodeFactIndex.EdgeKind.DIRECT;
            } else {
                for (String candidate : classes.keySet()) {
                    if (++resolutionChecks > CALL_GRAPH_RESOLUTION_BUDGET) {
                        stopReasons.add("CALL_GRAPH_RESOLUTION_BUDGET_EXHAUSTED");
                        return result;
                    }
                    if (!isSubtype(candidate, edge.targetOwner(), classes)) continue;
                    MethodId implementation = findImplementation(candidate, edge.targetName(),
                            edge.targetDescriptor(), methods, classes);
                    if (implementation != null && !targets.contains(implementation)) targets.add(implementation);
                }
                kind = targets.isEmpty() ? BytecodeFactIndex.EdgeKind.UNRESOLVED : BytecodeFactIndex.EdgeKind.CHA;
            }
            if (targets.isEmpty()) {
                targets = List.of(new MethodId(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
            }
            for (MethodId target : targets) {
                String key = edge.evidence().stableKey() + "->" + target.display() + ":" + kind;
                if (!dedupe.add(key)) continue;
                if (result.size() >= CALL_GRAPH_EDGE_BUDGET) {
                    stopReasons.add("CALL_GRAPH_EDGE_BUDGET_EXHAUSTED");
                    return result;
                }
                String limitation = kind == BytecodeFactIndex.EdgeKind.UNRESOLVED
                        ? "target is outside the artifact or dynamically unresolved"
                        : kind == BytecodeFactIndex.EdgeKind.CHA
                        ? "artifact-local CHA target; runtime receiver type is not proven"
                        : "artifact-local exact static/special target";
                result.add(new BytecodeFactIndex.ResolvedCallEdge(edge.callerOwner(), edge.callerName(),
                        edge.callerDescriptor(), edge.targetOwner(), target.owner, target.name,
                        target.descriptor, kind, limitation, edge.evidence()));
            }
        }
        return result;
    }

    private static MethodId findImplementation(String owner, String name, String descriptor,
                                               Map<MethodId, BytecodeFactIndex.MethodFact> methods,
                                               Map<String, BytecodeFactIndex.ClassFact> classes) {
        String current = owner;
        Set<String> seen = new HashSet<>();
        while (current != null && seen.add(current)) {
            MethodId candidate = new MethodId(current, name, descriptor);
            if (methods.containsKey(candidate)) return candidate;
            BytecodeFactIndex.ClassFact fact = classes.get(current);
            current = fact == null ? null : fact.superClassName();
        }
        return null;
    }

    private static boolean isSubtype(String candidate, String expected,
                                     Map<String, BytecodeFactIndex.ClassFact> classes) {
        if (candidate.equals(expected)) return true;
        ArrayDeque<String> pending = new ArrayDeque<>();
        pending.add(candidate);
        Set<String> seen = new HashSet<>();
        while (!pending.isEmpty()) {
            String current = pending.removeFirst();
            if (!seen.add(current)) continue;
            BytecodeFactIndex.ClassFact fact = classes.get(current);
            if (fact == null) continue;
            if (expected.equals(fact.superClassName()) || fact.interfaces().contains(expected)) return true;
            if (fact.superClassName() != null) pending.add(fact.superClassName());
            pending.addAll(fact.interfaces());
        }
        return false;
    }

    private static boolean isController(ClassMetadata metadata) {
        return metadata.annotations().stream().map(ClassMetadata.AnnotationMetadata::typeName)
                .anyMatch(name -> name.equals("org.springframework.stereotype.Controller")
                        || name.equals("org.springframework.web.bind.annotation.RestController"));
    }

    private static boolean isMapping(List<ClassMetadata.AnnotationMetadata> annotations) {
        return annotations.stream().map(ClassMetadata.AnnotationMetadata::typeName).anyMatch(name ->
                name.equals("org.springframework.web.bind.annotation.RequestMapping")
                        || name.startsWith("org.springframework.web.bind.annotation.")
                        && name.endsWith("Mapping"));
    }

    private static BytecodeFactIndex.TaintStep step(String kind, BytecodeFactIndex.CallEdge edge,
                                                    String explanation) {
        return new BytecodeFactIndex.TaintStep(kind,
                edge.targetOwner() + "#" + edge.targetName() + edge.targetDescriptor(),
                edge.kind().name(), edge.evidence().stableKey(), explanation);
    }

    private static boolean returnsValue(String descriptor) {
        int close = descriptor.indexOf(')');
        return close >= 0 && close + 1 < descriptor.length() && descriptor.charAt(close + 1) != 'V';
    }

    private static int parameterCount(String descriptor) {
        int count = 0;
        int position = 1;
        while (position < descriptor.length() && descriptor.charAt(position) != ')') {
            while (descriptor.charAt(position) == '[') position++;
            if (descriptor.charAt(position++) == 'L') {
                position = descriptor.indexOf(';', position) + 1;
                if (position == 0) return 0;
            }
            count++;
        }
        return count;
    }

    record Result(List<BytecodeFactIndex.ResolvedCallEdge> graph,
                  List<BytecodeFactIndex.TaintPath> paths,
                  BytecodeFactIndex.AnalysisCoverage coverage) { }

    private record MethodId(String owner, String name, String descriptor) {
        private String display() { return owner + "#" + name + descriptor; }
    }

    private record State(MethodId source, int sourceParameter, MethodId method,
                         int parameter, int callDepth, List<BytecodeFactIndex.TaintStep> steps) { }
}
