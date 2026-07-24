package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Deterministic, static-only pre-analysis. It never loads or executes artifact classes. */
public final class PreAnalysisService {
    private static final String CONTROLLER = "org.springframework.stereotype.Controller";
    private static final String REST_CONTROLLER = "org.springframework.web.bind.annotation.RestController";
    private static final String REQUEST_MAPPING = "org.springframework.web.bind.annotation.RequestMapping";
    private static final String MAPPING_PACKAGE = "org.springframework.web.bind.annotation.";
    private static final Set<String> SHORTCUT_MAPPINGS = Set.of(
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping");
    private static final Set<String> PARAMETER_ANNOTATIONS = Set.of(
            "RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue",
            "RequestPart", "ModelAttribute");
    private static final int MAX_DISCOVERED_ENTRIES = 10_000;
    private static final int MAX_MAPPING_PATHS = 64;
    private static final int MAX_PATH_COMBINATIONS = 1_024;
    private static final int MAX_DISPLAY_VALUE = 256;

    public PreAnalysisResult analyze(PreAnalysisInput input) {
        List<Evidence> evidence = new ArrayList<>();
        List<Entrypoint> entries = new ArrayList<>();
        List<DependencyAccess> dependencies = new ArrayList<>();
        List<Sink> sinks = new ArrayList<>();
        List<PermissionRequirement> permissions = new ArrayList<>();
        List<BytecodeFactIndex.ClassFact> classFacts = new ArrayList<>();
        List<BytecodeFactIndex.FieldFact> fieldFacts = new ArrayList<>();
        List<BytecodeFactIndex.MethodFact> methodFacts = new ArrayList<>();
        List<BytecodeFactIndex.MemberAccessFact> memberAccessFacts = new ArrayList<>();
        List<BytecodeFactIndex.CallEdge> callEdges = new ArrayList<>();
        List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics = new ArrayList<>();
        int index = 0;
        Set<String> classesWithValidAnnotationMetadata = new LinkedHashSet<>();
        for (ClassMetadata metadata : input.classMetadata()) {
            if (metadata.classFact() != null) classFacts.add(metadata.classFact());
            fieldFacts.addAll(metadata.fieldFacts());
            methodFacts.addAll(metadata.methodFacts());
            memberAccessFacts.addAll(metadata.memberAccessFacts());
            callEdges.addAll(metadata.callEdges());
            unresolvedDynamics.addAll(metadata.unresolvedDynamics());
            if (!metadata.annotationMetadataValid()) continue;
            classesWithValidAnnotationMetadata.add(metadata.className());
            index = discoverAnnotatedEntries(metadata, evidence, entries, permissions, index);
            if (entries.size() > MAX_DISCOVERED_ENTRIES) {
                throw new IllegalArgumentException("annotation metadata produced too many entrypoints");
            }
        }
        for (String className : input.classNames()) {
            if (className == null || className.isBlank()) {
                continue;
            }
            String lower = className.toLowerCase(Locale.ROOT);
            String evidenceId = "inf-" + (++index);
            evidence.add(new Evidence(evidenceId, ProvenanceKind.INFERENCE, "class-name:" + limit(className),
                    0.72, "rule-based pre-analysis; runtime registration not observed"));
            if (!classesWithValidAnnotationMetadata.contains(className)
                    && (lower.contains("controller") || lower.contains("resource") || lower.contains("endpoint"))) {
                String inferredName = simpleName(className).toLowerCase(Locale.ROOT).replace("controller", "").trim();
                if (inferredName.isEmpty()) inferredName = "unknown";
                String route = "/inferred/" + safeRoutePart(inferredName);
                String entryId = "entry-" + index;
                entries.add(new Entrypoint(entryId, "HTTP", "UNKNOWN", route, className,
                        List.of("request parameters inferred from bytecode metadata"), List.of(), List.of(evidenceId),
                        0.72, VerificationStatus.STATIC_INFERRED));
                if (lower.contains("admin") || lower.contains("secure")) {
                    permissions.add(new PermissionRequirement(entryId, List.of("ROLE_ADMIN"), List.of(), List.of(), List.of(evidenceId), 0.64));
                }
            }
            if (lower.contains("repository") || lower.contains("dao") || lower.contains("jdbc") || lower.contains("datasource")) {
                dependencies.add(new DependencyAccess("dep-" + index, "DATABASE", "unknown", "read/write",
                        "MOCK", List.of("unknown (inferred; inspect runtime SQL)"), List.of(evidenceId), 0.58, VerificationStatus.STATIC_INFERRED));
            }
            if (lower.contains("file") || lower.contains("upload") || lower.contains("path")) {
                sinks.add(new Sink("sink-" + index, "FILE", limit(className), "class-name rule", 0.62,
                        List.of(evidenceId), VerificationStatus.STATIC_INFERRED));
            }
            if (lower.contains("runtime") || lower.contains("processbuilder") || lower.contains("exec")) {
                sinks.add(new Sink("sink-" + index, "COMMAND", limit(className), "class-name rule", 0.66,
                        List.of(evidenceId), VerificationStatus.STATIC_INFERRED));
            }
        }
        for (String line : input.configurationLines()) {
            if (line == null || line.isBlank()) continue;
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("spring.datasource") || lower.contains("jdbc:")) {
                String id = "cfg-" + (++index);
                String safeLine = limit(redactConfiguration(line));
                evidence.add(new Evidence(id, ProvenanceKind.FACT, "configuration", 1.0, safeLine));
                dependencies.add(new DependencyAccess("dep-" + index, "DATABASE", safeLine, "configured", "MOCK",
                        List.of(), List.of(id), 1.0, VerificationStatus.STATIC_INFERRED));
            }
        }
        BytecodeFactIndex factIndex = new BytecodeFactIndex(classFacts, fieldFacts, methodFacts,
                memberAccessFacts, callEdges, unresolvedDynamics);
        return new PreAnalysisResult(new EntryCatalog(entries, evidence), new DependencyMap(dependencies),
                new SinkCatalog(sinks), new PermissionMatrix(permissions), factIndex);
    }

    private int discoverAnnotatedEntries(ClassMetadata metadata, List<Evidence> evidence,
                                         List<Entrypoint> entries,
                                         List<PermissionRequirement> permissions, int index) {
        if (!hasAnnotation(metadata.annotations(), CONTROLLER)
                && !hasAnnotation(metadata.annotations(), REST_CONTROLLER)) {
            return index;
        }
        ClassMetadata.AnnotationMetadata classMapping = findAnnotation(metadata.annotations(), REQUEST_MAPPING);
        List<String> classPaths = mappingPaths(classMapping);
        List<String> classMethods = requestMethods(classMapping);
        PermissionData classPermission = permissions(metadata.annotations());
        for (ClassMetadata.MethodMetadata method : metadata.methods()) {
            ClassMetadata.AnnotationMetadata methodMapping = findMapping(method.annotations());
            if (methodMapping == null) continue;
            List<String> routes = mergePaths(classPaths, mappingPaths(methodMapping));
            List<String> httpMethods = mergeHttpMethods(classMethods, mappingMethods(methodMapping));
            if (httpMethods.isEmpty()) continue;
            PermissionData methodPermission = permissions(method.annotations());
            PermissionData combinedPermission = classPermission.merge(methodPermission);
            List<String> parameters = describeParameters(method.parameters());
            for (String route : routes) {
                for (String httpMethod : httpMethods) {
                    if (entries.size() >= MAX_DISCOVERED_ENTRIES) {
                        throw new IllegalArgumentException("annotation metadata produced too many entrypoints");
                    }
                    String entryId = "entry-ann-" + (++index);
                    String mappingEvidenceId = "ann-" + index;
                    evidence.add(new Evidence(mappingEvidenceId, ProvenanceKind.FACT,
                            "classfile-annotation:" + metadata.className() + "#" + safeSymbol(method.name()),
                            1.0, "Spring MVC mapping annotation present in classfile"));
                    List<String> refs = new ArrayList<>();
                    refs.add(mappingEvidenceId);
                    String permissionEvidenceId = null;
                    if (!combinedPermission.preconditions().isEmpty()) {
                        permissionEvidenceId = "perm-" + index;
                        evidence.add(new Evidence(permissionEvidenceId, ProvenanceKind.FACT,
                                "classfile-annotation:" + metadata.className() + "#" + safeSymbol(method.name()),
                                1.0, "permission annotation present in classfile"));
                        refs.add(permissionEvidenceId);
                    }
                    entries.add(new Entrypoint(entryId, "HTTP", httpMethod, route, metadata.className(),
                            parameters, combinedPermission.preconditions(), refs, 0.95,
                            VerificationStatus.STATIC_INFERRED));
                    if (permissionEvidenceId != null) {
                        permissions.add(new PermissionRequirement(entryId, combinedPermission.roles(),
                                List.of(), combinedPermission.states(), List.of(permissionEvidenceId), 1.0));
                    }
                }
            }
        }
        return index;
    }

    private static ClassMetadata.AnnotationMetadata findMapping(List<ClassMetadata.AnnotationMetadata> annotations) {
        for (ClassMetadata.AnnotationMetadata annotation : annotations) {
            if (annotation.typeName().equals(REQUEST_MAPPING)) return annotation;
            String simple = simpleName(annotation.typeName());
            if (annotation.typeName().startsWith(MAPPING_PACKAGE) && SHORTCUT_MAPPINGS.contains(simple)) {
                return annotation;
            }
        }
        return null;
    }

    private static ClassMetadata.AnnotationMetadata findAnnotation(
            List<ClassMetadata.AnnotationMetadata> annotations, String type) {
        for (ClassMetadata.AnnotationMetadata annotation : annotations) {
            if (annotation.typeName().equals(type)) return annotation;
        }
        return null;
    }

    private static boolean hasAnnotation(List<ClassMetadata.AnnotationMetadata> annotations, String type) {
        return findAnnotation(annotations, type) != null;
    }

    private static List<String> mappingPaths(ClassMetadata.AnnotationMetadata annotation) {
        if (annotation == null) return List.of("");
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        for (String value : annotation.values("path")) paths.add(normalizeRoute(value));
        for (String value : annotation.values("value")) paths.add(normalizeRoute(value));
        if (paths.size() > MAX_MAPPING_PATHS) {
            throw new IllegalArgumentException("mapping annotation contains too many paths");
        }
        if (paths.isEmpty()) paths.add("");
        return List.copyOf(paths);
    }

    private static List<String> requestMethods(ClassMetadata.AnnotationMetadata annotation) {
        if (annotation == null) return List.of("UNKNOWN");
        List<String> methods = sanitizeMethods(annotation.values("method"));
        return methods.isEmpty() ? List.of("UNKNOWN") : methods;
    }

    private static List<String> mappingMethods(ClassMetadata.AnnotationMetadata annotation) {
        String simple = simpleName(annotation.typeName());
        if (SHORTCUT_MAPPINGS.contains(simple)) {
            return List.of(simple.substring(0, simple.length() - "Mapping".length()).toUpperCase(Locale.ROOT));
        }
        return requestMethods(annotation);
    }

    private static List<String> sanitizeMethods(List<String> values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String value : values) {
            String method = value.toUpperCase(Locale.ROOT);
            if (Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE").contains(method)) {
                result.add(method);
            }
        }
        return List.copyOf(result);
    }

    private static List<String> mergeHttpMethods(List<String> classMethods, List<String> methodMethods) {
        boolean classUnknown = classMethods.contains("UNKNOWN");
        boolean methodUnknown = methodMethods.contains("UNKNOWN");
        if (classUnknown && methodUnknown) return List.of("UNKNOWN");
        if (classUnknown) return methodMethods;
        if (methodUnknown) return classMethods;
        LinkedHashSet<String> result = new LinkedHashSet<>(classMethods);
        result.retainAll(methodMethods);
        return List.copyOf(result);
    }

    private static List<String> mergePaths(List<String> classPaths, List<String> methodPaths) {
        if ((long) classPaths.size() * methodPaths.size() > MAX_PATH_COMBINATIONS) {
            throw new IllegalArgumentException("mapping annotations produce too many path combinations");
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String classPath : classPaths) {
            for (String methodPath : methodPaths) {
                String merged = (classPath + "/" + methodPath).replaceAll("/+", "/");
                if (!merged.startsWith("/")) merged = "/" + merged;
                if (merged.length() > 1 && merged.endsWith("/")) merged = merged.substring(0, merged.length() - 1);
                result.add(limit(merged));
            }
        }
        return List.copyOf(result);
    }

    private static List<String> describeParameters(List<ClassMetadata.ParameterMetadata> parameters) {
        List<String> result = new ArrayList<>(parameters.size());
        for (ClassMetadata.ParameterMetadata parameter : parameters) {
            ClassMetadata.AnnotationMetadata recognized = null;
            for (ClassMetadata.AnnotationMetadata annotation : parameter.annotations()) {
                if (annotation.typeName().startsWith(MAPPING_PACKAGE)
                        && PARAMETER_ANNOTATIONS.contains(simpleName(annotation.typeName()))) {
                    recognized = annotation;
                    break;
                }
            }
            String candidate = recognized == null ? null : first(recognized.values("name"));
            if (candidate == null && recognized != null) candidate = first(recognized.values("value"));
            if (candidate == null || candidate.isBlank()) candidate = parameter.nameCandidate();
            if (candidate == null || candidate.isBlank()) candidate = "arg" + parameter.position();
            String kind = recognized == null ? "unannotated" : simpleName(recognized.typeName());
            result.add("position=" + parameter.position() + ",kind=" + kind + ",name=" + limit(candidate));
        }
        return List.copyOf(result);
    }

    private static PermissionData permissions(List<ClassMetadata.AnnotationMetadata> annotations) {
        List<String> preconditions = new ArrayList<>();
        List<String> roles = new ArrayList<>();
        List<String> states = new ArrayList<>();
        for (ClassMetadata.AnnotationMetadata annotation : annotations) {
            String type = annotation.typeName();
            if (type.equals("org.springframework.security.access.prepost.PreAuthorize")) {
                for (String expression : annotation.values("value")) {
                    String safe = limit(expression);
                    preconditions.add("PreAuthorize(" + safe + ")");
                    states.add("EXPR:" + safe);
                }
            } else if (type.equals("org.springframework.security.access.annotation.Secured")
                    || type.equals("javax.annotation.security.RolesAllowed")
                    || type.equals("jakarta.annotation.security.RolesAllowed")) {
                String label = simpleName(type);
                for (String role : annotation.values("value")) {
                    String safe = limit(role);
                    preconditions.add(label + "(" + safe + ")");
                    roles.add(safe);
                }
            }
        }
        return new PermissionData(List.copyOf(preconditions), List.copyOf(roles), List.copyOf(states));
    }

    private static String first(List<String> values) {
        return values.isEmpty() ? null : values.get(0);
    }

    private static String normalizeRoute(String value) {
        String safe = limit(value == null ? "" : value.trim());
        if (safe.isEmpty() || safe.equals("/")) return "";
        return safe.startsWith("/") ? safe : "/" + safe;
    }

    private static String safeSymbol(String value) {
        return limit(value).replaceAll("[^A-Za-z0-9_$<>-]", "?");
    }

    private static String limit(String value) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; value != null && i < value.length() && result.length() < MAX_DISPLAY_VALUE; i++) {
            char c = value.charAt(i);
            result.append(Character.isISOControl(c) ? '?' : c);
        }
        return result.toString();
    }

    private record PermissionData(List<String> preconditions, List<String> roles, List<String> states) {
        private PermissionData merge(PermissionData other) {
            LinkedHashSet<String> conditions = new LinkedHashSet<>(preconditions);
            conditions.addAll(other.preconditions);
            LinkedHashSet<String> mergedRoles = new LinkedHashSet<>(roles);
            mergedRoles.addAll(other.roles);
            LinkedHashSet<String> mergedStates = new LinkedHashSet<>(states);
            mergedStates.addAll(other.states);
            return new PermissionData(List.copyOf(conditions), List.copyOf(mergedRoles), List.copyOf(mergedStates));
        }
    }

    private static String simpleName(String name) {
        int slash = Math.max(name.lastIndexOf('.'), name.lastIndexOf('/'));
        return slash < 0 ? name : name.substring(slash + 1);
    }

    private static String safeRoutePart(String value) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_') result.append(c);
        }
        return result.length() == 0 ? "unknown" : result.toString();
    }

    private static String redactConfiguration(String line) {
        int equals = line.indexOf('=');
        int colon = line.indexOf(':');
        int separator = equals < 0 ? colon : colon < 0 ? equals : Math.min(equals, colon);
        if (separator > 0) {
            String key = line.substring(0, separator).trim();
            if (key.matches("(?i).*(password|passwd|secret|token|credential|private[-_.]?key).*")) {
                return key + line.substring(separator, separator + 1) + "<redacted>";
            }
        }
        return line.replaceAll("(?i)(://[^:/\\s]+:)[^@\\s]+@", "$1<redacted>@");
    }
}
