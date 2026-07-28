package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.model.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
    private static final int MAX_DISCOVERED_SINKS = 20_000;
    private static final int MAX_MAPPING_PATHS = 64;
    private static final int MAX_PATH_COMBINATIONS = 1_024;
    private static final int MAX_DISPLAY_VALUE = 256;

    public PreAnalysisResult analyze(PreAnalysisInput input) {
        // P1-03: ensure versioned default providers are installed (thin SPI; discovery stays here).
        ProviderRegistry.ensureDefaults();
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
        Map<String, Integer> sinkByCallEvidence = new LinkedHashMap<>();
        int index = 0;
        Set<String> classesWithValidAnnotationMetadata = new LinkedHashSet<>();
        for (ClassMetadata metadata : input.classMetadata()) {
            if (metadata.classFact() != null) classFacts.add(metadata.classFact());
            fieldFacts.addAll(metadata.fieldFacts());
            methodFacts.addAll(metadata.methodFacts());
            memberAccessFacts.addAll(metadata.memberAccessFacts());
            callEdges.addAll(metadata.callEdges());
            unresolvedDynamics.addAll(metadata.unresolvedDynamics());
            for (BytecodeFactIndex.CallEdge edge : metadata.callEdges()) {
                JvmSinkSignatures.Match match = JvmSinkSignatures.match(edge);
                if (match == null) continue;
                if (sinks.size() >= MAX_DISCOVERED_SINKS) {
                    throw new IllegalArgumentException("classfile metadata produced too many sink candidates");
                }
                String evidenceId = "call-" + (++index);
                String target = edge.targetOwner() + "#" + edge.targetName() + edge.targetDescriptor();
                String caller = edge.callerOwner() + "#" + edge.callerName() + edge.callerDescriptor();
                evidence.add(new Evidence(evidenceId, ProvenanceKind.FACT,
                        "classfile-call:" + limit(edge.evidence().stableKey()), 1.0,
                        "sensitive API invocation present: " + limit(target)
                                + "; symbolic edge only; runtime reachability and input control not established"));
                sinks.add(new Sink("sink-call-" + index, match.category(),
                        limit(caller + " -> " + target),
                        "bytecode-invoke:" + match.ruleId() + "; edge=" + edge.kind().name()
                                + "; no taint or runtime proof",
                        match.confidence(), List.of(evidenceId), VerificationStatus.STATIC_INFERRED));
                sinkByCallEvidence.put(edge.evidence().stableKey(), sinks.size() - 1);
            }
            if (!metadata.annotationMetadataValid()) continue;
            classesWithValidAnnotationMetadata.add(metadata.className());
            index = discoverAnnotatedEntries(metadata, evidence, entries, sinks, permissions, index);
            if (entries.size() > MAX_DISCOVERED_ENTRIES) {
                throw new IllegalArgumentException("annotation metadata produced too many entrypoints");
            }
        }
        for (String className : input.classNames()) {
            if (className == null || className.isBlank()) {
                continue;
            }
            // Class-name rules are a last-resort fallback for malformed or otherwise
            // unreadable classfiles. Applying them to valid framework classes (for
            // example Spring Boot's File/Launcher infrastructure) produces noisy,
            // unbound pseudo-findings that are not evidence of application behavior.
            if (classesWithValidAnnotationMetadata.contains(className)) {
                continue;
            }
            String lower = className.toLowerCase(Locale.ROOT);
            String evidenceId = "inf-" + (++index);
            evidence.add(new Evidence(evidenceId, ProvenanceKind.INFERENCE, "class-name:" + limit(className),
                    0.72, "rule-based pre-analysis; runtime registration not observed"));
            if (lower.contains("controller") || lower.contains("resource") || lower.contains("endpoint")) {
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
            if (lower.contains("jwt") || lower.contains("jsonwebtoken") || lower.contains("tokenutil")) {
                sinks.add(new Sink("sink-" + index, "JWT", limit(className),
                        "class-name rule; JWT utility presence only, no bypass proof", 0.60,
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
            if (lower.contains("jwt") && (lower.contains("secret") || lower.contains("key")
                    || lower.contains("signing") || lower.contains("token"))) {
                if (sinks.size() >= MAX_DISCOVERED_SINKS) {
                    throw new IllegalArgumentException("classfile metadata produced too many sink candidates");
                }
                String id = "cfg-" + (++index);
                String safeLine = limit(redactConfiguration(line));
                evidence.add(new Evidence(id, ProvenanceKind.FACT, "configuration", 1.0, safeLine));
                sinks.add(new Sink("sink-cfg-" + index, "JWT", safeLine,
                        "configuration JWT secret/key material reference; strength and verification not proven",
                        0.70, List.of(id), VerificationStatus.STATIC_INFERRED));
            }
        }
        InterproceduralTaintAnalyzer.Result interprocedural =
                new InterproceduralTaintAnalyzer().analyze(input.classMetadata());
        BytecodeFactIndex.AnalysisCoverage coverage = interprocedural.coverage();
        evidence.add(new Evidence("call-graph-summary", ProvenanceKind.FACT, "classfile-call-graph",
                1.0, "artifact-local call graph edges=" + interprocedural.graph().size()
                        + "; direct/CHA/unresolved are retained with budget and stop reasons"));
        evidence.add(new Evidence("taint-summary", ProvenanceKind.INFERENCE, "classfile-taint-summary",
                0.78, "bounded cross-method taint paths=" + interprocedural.paths().size()
                        + "; states=" + coverage.taintStatesVisited() + "/" + coverage.taintStateBudget()
                        + "; complete=" + coverage.complete() + "; stopReasons="
                        + String.join(",", coverage.stopReasons())));
        for (BytecodeFactIndex.TaintPath path : interprocedural.paths()) {
            if (path.steps().isEmpty()) continue;
            String callEvidence = path.steps().get(path.steps().size() - 1).evidence();
            Integer sinkPosition = sinkByCallEvidence.get(callEvidence);
            if (sinkPosition == null) continue;
            String pathEvidenceId = "flow-" + path.id();
            evidence.add(new Evidence(pathEvidenceId, ProvenanceKind.INFERENCE,
                    "classfile-taint:" + path.id(), 0.78,
                    "bounded interprocedural parameter-origin path to " + path.sinkOwner() + "#"
                            + path.sinkMethod() + path.sinkDescriptor()
                            + "; static input control only; runtime reachability and exploitability not established"));
            Sink candidate = sinks.get(sinkPosition);
            List<String> refs = new ArrayList<>(candidate.evidenceRefs());
            refs.add(pathEvidenceId);
            sinks.set(sinkPosition, new Sink(candidate.id(), candidate.category(), candidate.symbol(),
                    candidate.source() + "; taint-path=" + path.id() + "; bounded static inference",
                    Math.max(candidate.confidence(), 0.78), refs, VerificationStatus.STATIC_INFERRED));
        }
        BytecodeFactIndex factIndex = new BytecodeFactIndex(classFacts, fieldFacts, methodFacts,
                memberAccessFacts, callEdges, unresolvedDynamics, interprocedural.graph(),
                interprocedural.paths(), coverage);
        return new PreAnalysisResult(new EntryCatalog(entries, evidence), new DependencyMap(dependencies),
                new SinkCatalog(sinks), new PermissionMatrix(permissions), factIndex);
    }

    private int discoverAnnotatedEntries(ClassMetadata metadata, List<Evidence> evidence,
                                         List<Entrypoint> entries, List<Sink> sinks,
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
            List<String> rawParameters = describeParameters(method.parameters());
            List<String> flowHints = List.of(
                    metadata.className() + "#" + method.name(),
                    String.join(" ", rawParameters));
            List<String> parameters = BranchConstraintHarvester.harvest(rawParameters, flowHints)
                    .stream()
                    .map(ParameterSpec::toLegacyEncoding)
                    .toList();
            if (parameters.isEmpty()) parameters = rawParameters;
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
                    } else if (sinks.size() < MAX_DISCOVERED_SINKS) {
                        // Mapped entry without recognizable auth annotation — gap signal only.
                        String gapEvidenceId = "auth-gap-" + index;
                        evidence.add(new Evidence(gapEvidenceId, ProvenanceKind.FACT,
                                "classfile-annotation:" + metadata.className() + "#" + safeSymbol(method.name()),
                                0.72, "HTTP mapping present without PreAuthorize/Secured/RolesAllowed/Blade auth annotation"));
                        sinks.add(new Sink("sink-auth-gap-" + index, "AUTH_GAP",
                                limit(metadata.className() + "#" + method.name() + " " + httpMethod + " " + route),
                                "auth annotation absent on mapped entry; anonymous reachability not proven",
                                0.62, List.of(gapEvidenceId, mappingEvidenceId),
                                VerificationStatus.STATIC_INFERRED));
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
            String simple = simpleName(type);
            if (type.equals("org.springframework.security.access.prepost.PreAuthorize")
                    || type.equals("org.springframework.security.access.prepost.PostAuthorize")) {
                for (String expression : annotation.values("value")) {
                    String safe = limit(expression);
                    preconditions.add(simple + "(" + safe + ")");
                    states.add("EXPR:" + safe);
                }
            } else if (type.equals("org.springframework.security.access.annotation.Secured")
                    || type.equals("javax.annotation.security.RolesAllowed")
                    || type.equals("jakarta.annotation.security.RolesAllowed")) {
                for (String role : annotation.values("value")) {
                    String safe = limit(role);
                    preconditions.add(simple + "(" + safe + ")");
                    roles.add(safe);
                }
            } else if (type.startsWith("org.springblade.core.secure.annotation.")
                    || type.equals("org.springblade.core.secure.annotation.PreAuth")
                    || "PreAuth".equals(simple) || "IsAdmin".equals(simple)
                    || "isAuth".equals(simple) || "IsAuth".equals(simple)) {
                List<String> values = annotation.values("value");
                if (values.isEmpty()) values = annotation.values("role");
                if (values.isEmpty()) {
                    preconditions.add(simple);
                    states.add("BLADE:" + simple);
                } else {
                    for (String value : values) {
                        String safe = limit(value);
                        preconditions.add(simple + "(" + safe + ")");
                        if (safe.startsWith("hasRole") || safe.startsWith("ROLE_")) roles.add(safe);
                        else states.add("BLADE:" + safe);
                    }
                }
            } else if (type.equals("javax.annotation.security.PermitAll")
                    || type.equals("jakarta.annotation.security.PermitAll")) {
                preconditions.add("PermitAll");
                states.add("PERMIT_ALL");
            } else if (type.equals("javax.annotation.security.DenyAll")
                    || type.equals("jakarta.annotation.security.DenyAll")) {
                preconditions.add("DenyAll");
                states.add("DENY_ALL");
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
