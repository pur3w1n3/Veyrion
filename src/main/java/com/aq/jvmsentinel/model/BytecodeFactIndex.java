package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * Bounded, load-free facts decoded from classfiles. Call edges are symbolic:
 * this index does not resolve class paths or claim runtime dispatch.
 */
public record BytecodeFactIndex(
        List<ClassFact> classes,
        List<FieldFact> fields,
        List<MethodFact> methods,
        List<MemberAccessFact> memberAccesses,
        List<CallEdge> callEdges,
        List<UnresolvedDynamicFact> unresolvedDynamics) {

    public static final BytecodeFactIndex EMPTY =
            new BytecodeFactIndex(List.of(), List.of(), List.of(), List.of(), List.of(), List.of());

    public BytecodeFactIndex {
        classes = copy(classes);
        fields = copy(fields);
        methods = copy(methods);
        memberAccesses = copy(memberAccesses);
        callEdges = copy(callEdges);
        unresolvedDynamics = copy(unresolvedDynamics);
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
        DIRECT, CONSERVATIVE_CHA, UNRESOLVED
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

    private static void require(String... values) {
        for (String value : values) Objects.requireNonNull(value, "fact value");
    }
}
