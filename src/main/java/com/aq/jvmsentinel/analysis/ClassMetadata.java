package com.aq.jvmsentinel.analysis;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable metadata decoded directly from a classfile without loading the class. */
public record ClassMetadata(
        String className,
        boolean annotationMetadataValid,
        List<AnnotationMetadata> annotations,
        List<MethodMetadata> methods) {

    public ClassMetadata {
        Objects.requireNonNull(className, "className");
        annotations = List.copyOf(annotations == null ? List.of() : annotations);
        methods = List.copyOf(methods == null ? List.of() : methods);
    }

    public static ClassMetadata invalid(String fallbackClassName) {
        return new ClassMetadata(fallbackClassName, false, List.of(), List.of());
    }

    public record MethodMetadata(
            String name,
            String descriptor,
            List<AnnotationMetadata> annotations,
            List<ParameterMetadata> parameters) {
        public MethodMetadata {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(descriptor, "descriptor");
            annotations = List.copyOf(annotations == null ? List.of() : annotations);
            parameters = List.copyOf(parameters == null ? List.of() : parameters);
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
}
