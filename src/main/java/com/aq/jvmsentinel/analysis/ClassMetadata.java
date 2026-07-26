package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable metadata decoded directly from a classfile without loading the class. */
public record ClassMetadata(
        String className,
        boolean annotationMetadataValid,
        List<AnnotationMetadata> annotations,
        List<MethodMetadata> methods,
        BytecodeFactIndex.ClassFact classFact,
        List<BytecodeFactIndex.FieldFact> fieldFacts,
        List<BytecodeFactIndex.MethodFact> methodFacts,
        List<BytecodeFactIndex.MemberAccessFact> memberAccessFacts,
        List<BytecodeFactIndex.CallEdge> callEdges,
        List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics,
        List<MethodFlowFact> methodFlows) {

    public ClassMetadata {
        Objects.requireNonNull(className, "className");
        annotations = List.copyOf(annotations == null ? List.of() : annotations);
        methods = List.copyOf(methods == null ? List.of() : methods);
        fieldFacts = List.copyOf(fieldFacts == null ? List.of() : fieldFacts);
        methodFacts = List.copyOf(methodFacts == null ? List.of() : methodFacts);
        memberAccessFacts = List.copyOf(memberAccessFacts == null ? List.of() : memberAccessFacts);
        callEdges = List.copyOf(callEdges == null ? List.of() : callEdges);
        unresolvedDynamics = List.copyOf(unresolvedDynamics == null ? List.of() : unresolvedDynamics);
        methodFlows = List.copyOf(methodFlows == null ? List.of() : methodFlows);
    }

    public ClassMetadata(String className, boolean annotationMetadataValid,
                         List<AnnotationMetadata> annotations, List<MethodMetadata> methods,
                         BytecodeFactIndex.ClassFact classFact,
                         List<BytecodeFactIndex.FieldFact> fieldFacts,
                         List<BytecodeFactIndex.MethodFact> methodFacts,
                         List<BytecodeFactIndex.MemberAccessFact> memberAccessFacts,
                         List<BytecodeFactIndex.CallEdge> callEdges,
                         List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics) {
        this(className, annotationMetadataValid, annotations, methods, classFact, fieldFacts,
                methodFacts, memberAccessFacts, callEdges, unresolvedDynamics, List.of());
    }

    public static ClassMetadata invalid(String fallbackClassName) {
        return new ClassMetadata(fallbackClassName, false, List.of(), List.of(), null,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    public record MethodMetadata(
            String name,
            String descriptor,
            int accessFlags,
            List<AnnotationMetadata> annotations,
            List<ParameterMetadata> parameters) {
        public MethodMetadata {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(descriptor, "descriptor");
            annotations = List.copyOf(annotations == null ? List.of() : annotations);
            parameters = List.copyOf(parameters == null ? List.of() : parameters);
        }

        public MethodMetadata(String name, String descriptor, List<AnnotationMetadata> annotations,
                              List<ParameterMetadata> parameters) {
            this(name, descriptor, 0, annotations, parameters);
        }
    }

    public record ParameterMetadata(
            int position,
            String nameCandidate,
            List<AnnotationMetadata> annotations) {
        public ParameterMetadata {
            if (position < 0) throw new IllegalArgumentException("position must be non-negative");
            annotations = List.copyOf(annotations == null ? List.of() : annotations);
        }
    }

    public record AnnotationMetadata(String typeName, Map<String, List<String>> values) {
        public AnnotationMetadata {
            Objects.requireNonNull(typeName, "typeName");
            Map<String, List<String>> copy = new LinkedHashMap<>();
            if (values != null) {
                values.forEach((key, value) -> copy.put(key, List.copyOf(value == null ? List.of() : value)));
            }
            values = Map.copyOf(copy);
        }

        public List<String> values(String name) {
            return values.getOrDefault(name, List.of());
        }
    }

    record MethodFlowFact(String owner, String name, String descriptor,
                          List<InvocationFlowFact> invocations, boolean complete) {
        MethodFlowFact {
            invocations = List.copyOf(invocations == null ? List.of() : invocations);
        }
    }

    record InvocationFlowFact(BytecodeFactIndex.CallEdge edge, List<Integer> receiverParameterOrigins,
                              List<List<Integer>> argumentParameterOrigins) {
        InvocationFlowFact {
            receiverParameterOrigins = List.copyOf(receiverParameterOrigins == null
                    ? List.of() : receiverParameterOrigins);
            List<List<Integer>> copy = new java.util.ArrayList<>();
            if (argumentParameterOrigins != null) {
                for (List<Integer> origins : argumentParameterOrigins) {
                    copy.add(List.copyOf(origins == null ? List.of() : origins));
                }
            }
            argumentParameterOrigins = List.copyOf(copy);
        }
    }
}
