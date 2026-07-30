package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * 从 classfile 解码的有界、无 load 事实。Call edge 为符号级：
 * 本 index 不解析 class path，也不声称 runtime dispatch。
 */
public record BytecodeFactIndex(
        List<ClassFact> classes,
        List<FieldFact> fields,
        List<MethodFact> methods,
        List<MemberAccessFact> memberAccesses,
        List<CallEdge> callEdges,
        List<UnresolvedDynamicFact> unresolvedDynamics,
        List<ResolvedCallEdge> artifactCallGraph,
        List<TaintPath> taintPaths,
        AnalysisCoverage analysisCoverage) {

    public static final BytecodeFactIndex EMPTY =
            new BytecodeFactIndex(List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), AnalysisCoverage.empty());

    public BytecodeFactIndex {
        classes = copy(classes);
        fields = copy(fields);
        methods = copy(methods);
        memberAccesses = copy(memberAccesses);
        callEdges = copy(callEdges);
        unresolvedDynamics = copy(unresolvedDynamics);
        artifactCallGraph = copy(artifactCallGraph);
        taintPaths = copy(taintPaths);
        analysisCoverage = analysisCoverage == null ? AnalysisCoverage.empty() : analysisCoverage;
    }

    public BytecodeFactIndex(List<ClassFact> classes, List<FieldFact> fields, List<MethodFact> methods,
                             List<MemberAccessFact> memberAccesses, List<CallEdge> callEdges,
                             List<UnresolvedDynamicFact> unresolvedDynamics) {
        this(classes, fields, methods, memberAccesses, callEdges, unresolvedDynamics,
                List.of(), List.of(), AnalysisCoverage.empty());
    }

    /** 将 index 视为 graph/flow 结果的消费者的兼容友好名称。 */
    public List<ResolvedCallEdge> callGraph() {
        return artifactCallGraph;
    }

    public List<TaintPath> interproceduralTaintPaths() {
        return taintPaths;
    }

    /**
     * 对 {@link #interproceduralTaintPaths()} 的有界 graph 投影。
     * 实现位于 {@code com.aq.jvmsentinel.analysis.TaintGraphProjector}，
     * 避免 model→analysis package 循环；本方法为稳定 call site。
     */
    public com.aq.jvmsentinel.analysis.TaintGraph taintGraph() {
        return com.aq.jvmsentinel.analysis.TaintGraphProjector.project(taintPaths);
    }

    private static <T> List<T> copy(List<T> values) {
        return List.copyOf(values == null ? List.of() : values);
    }

    public record ClassFact(String className, String superClassName, List<String> interfaces,
                            int accessFlags, String evidence) {
        public ClassFact {
            Objects.requireNonNull(className, "className");
            interfaces = copy(interfaces);
            Objects.requireNonNull(evidence, "evidence");
        }
    }

    public record FieldFact(String owner, String name, String descriptor, int accessFlags, String evidence) {
        public FieldFact {
            require(owner, name, descriptor, evidence);
        }
    }

    public record MethodFact(String owner, String name, String descriptor, int accessFlags, String evidence) {
        public MethodFact {
            require(owner, name, descriptor, evidence);
        }
    }

    public record InstructionEvidence(
            String className, String methodName, String methodDescriptor, int bytecodeOffset, int ordinal) {
        public InstructionEvidence {
            require(className, methodName, methodDescriptor);
            if (bytecodeOffset < -1 || ordinal < 0) {
                throw new IllegalArgumentException("evidence location is invalid");
            }
        }

        public String stableKey() {
            String location = bytecodeOffset < 0 ? "method-seq" : "bci-" + bytecodeOffset;
            return className + "#" + methodName + methodDescriptor + "@" + location + ":" + ordinal;
        }
    }

    public enum AccessKind {
        FIELD_READ, FIELD_WRITE, INVOKE_VIRTUAL, INVOKE_SPECIAL, INVOKE_STATIC, INVOKE_INTERFACE, INVOKE_DYNAMIC
    }

    public record MemberAccessFact(AccessKind kind, String targetOwner, String targetName,
                                   String targetDescriptor, InstructionEvidence evidence) {
        public MemberAccessFact {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(targetOwner, "targetOwner");
            require(targetName, targetDescriptor);
            Objects.requireNonNull(evidence, "evidence");
        }
    }

    public enum EdgeKind {
        DIRECT, CHA, CONSERVATIVE_CHA, UNRESOLVED
    }

    public record CallEdge(String callerOwner, String callerName, String callerDescriptor,
                           String targetOwner, String targetName, String targetDescriptor,
                           EdgeKind kind, String limitation, InstructionEvidence evidence) {
        public CallEdge {
            require(callerOwner, callerName, callerDescriptor, targetOwner, targetName, targetDescriptor, limitation);
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(evidence, "evidence");
        }
    }

    public record UnresolvedDynamicFact(String mechanism, String detail, InstructionEvidence evidence) {
        public UnresolvedDynamicFact {
            require(mechanism, detail);
            Objects.requireNonNull(evidence, "evidence");
        }
    }

    /** 仅针对本 artifact 中存在的 class 与 method 解析的 target。 */
    public record ResolvedCallEdge(String callerOwner, String callerName, String callerDescriptor,
                                   String declaredOwner, String targetOwner, String targetName,
                                   String targetDescriptor, EdgeKind kind, String limitation,
                                   InstructionEvidence evidence) {
        public ResolvedCallEdge {
            require(callerOwner, callerName, callerDescriptor, declaredOwner, targetOwner,
                    targetName, targetDescriptor, limitation);
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(evidence, "evidence");
        }
    }

    public record TaintStep(String kind, String symbol, String edgeKind,
                            String evidence, String explanation) {
        public TaintStep {
            require(kind, symbol, edgeKind, evidence, explanation);
        }
    }

    /** 静态 source-to-sink 候选。永非 runtime 或 replay verification。 */
    public record TaintPath(String id, String sourceOwner, String sourceMethod,
                            String sourceDescriptor, int sourceParameter, String sinkOwner,
                            String sinkMethod, String sinkDescriptor, String category,
                            List<TaintStep> steps, String status) {
        public TaintPath {
            require(id, sourceOwner, sourceMethod, sourceDescriptor, sinkOwner, sinkMethod,
                    sinkDescriptor, category, status);
            if (sourceParameter < 0) throw new IllegalArgumentException("sourceParameter must be non-negative");
            steps = copy(steps);
        }
    }

    public record AnalysisCoverage(int callGraphEdgeBudget, int taintStateBudget,
                                   int callGraphEdgesProduced, int taintStatesVisited,
                                   boolean complete, List<String> stopReasons) {
        public AnalysisCoverage {
            if (callGraphEdgeBudget < 0 || taintStateBudget < 0 || callGraphEdgesProduced < 0
                    || taintStatesVisited < 0) {
                throw new IllegalArgumentException("analysis coverage counts must be non-negative");
            }
            stopReasons = copy(stopReasons);
        }

        public static AnalysisCoverage empty() {
            return new AnalysisCoverage(0, 0, 0, 0, true, List.of());
        }
    }

    private static void require(String... values) {
        for (String value : values) Objects.requireNonNull(value, "fact value");
    }
}
