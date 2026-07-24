package com.aq.jvmsentinel.control;

import java.util.List;
import java.util.Objects;

/** Versioned wire DTOs exposed by {@link ControlPlaneServer}. */
public final class ApiDtos {
    public static final int SCHEMA_VERSION = 1;
    /** Event envelopes currently share the v1 wire contract; scope is still carried explicitly. */
    public static final int EVENT_SCHEMA_VERSION = SCHEMA_VERSION;
    public static final String STATIC_INFERRED = "STATIC_INFERRED";
    public static final String MOCK = "MOCK";

    private ApiDtos() { }

    public record ProjectDto(int schemaVersion, String projectId, String name, String createdAt,
                             String verificationStatus, String dependencyMode,
                             List<String> evidenceRefs, List<ArtifactDto> artifacts) {
        public ProjectDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(name, "name");
            requireText(createdAt, "createdAt");
            requireText(verificationStatus, "verificationStatus");
            requireText(dependencyMode, "dependencyMode");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            artifacts = List.copyOf(artifacts == null ? List.of() : artifacts);
        }
    }

    public record ArtifactDto(int schemaVersion, String projectId, String artifactId,
                              String artifactType, String artifactDigest, long sizeBytes,
                              boolean staticOnly, String registeredAt, String verificationStatus,
                              String dependencyMode, List<String> evidenceRefs) {
        public ArtifactDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactId, "artifactId");
            requireText(artifactType, "artifactType");
            requireText(artifactDigest, "artifactDigest");
            requireText(registeredAt, "registeredAt");
            requireText(verificationStatus, "verificationStatus");
            requireText(dependencyMode, "dependencyMode");
            if (sizeBytes < 0) throw new IllegalArgumentException("sizeBytes must not be negative");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        }
    }

    public record EntryDto(int schemaVersion, String projectId, String artifactDigest,
                           String scanId, String id, String protocol, String method,
                           String route, String declaringClass, String module,
                           List<String> parameters, List<String> preconditions,
                           String verificationStatus, double confidence, int coverage,
                           List<String> evidenceRefs) {
        public EntryDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(id, "id");
            requireText(protocol, "protocol");
            requireText(method, "method");
            requireText(route, "route");
            requireText(declaringClass, "declaringClass");
            requireText(module, "module");
            requireText(verificationStatus, "verificationStatus");
            parameters = List.copyOf(parameters == null ? List.of() : parameters);
            preconditions = List.copyOf(preconditions == null ? List.of() : preconditions);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            requireConfidence(confidence);
            if (coverage < 0 || coverage > 100) throw new IllegalArgumentException("coverage must be 0..100");
        }
    }

    public record DependencyDto(int schemaVersion, String projectId, String artifactDigest,
                                String scanId, String id, String kind, String target,
                                String accessType, String mode, List<String> fields,
                                String verificationStatus, double confidence,
                                List<String> evidenceRefs) {
        public DependencyDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(id, "id");
            requireText(kind, "kind");
            requireText(target, "target");
            requireText(accessType, "accessType");
            requireText(mode, "mode");
            requireText(verificationStatus, "verificationStatus");
            fields = List.copyOf(fields == null ? List.of() : fields);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            requireConfidence(confidence);
        }
    }

    public record SinkDto(int schemaVersion, String projectId, String artifactDigest,
                          String scanId, String id, String category, String symbol,
                          String source, String verificationStatus, double confidence,
                          List<String> evidenceRefs) {
        public SinkDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(id, "id");
            requireText(category, "category");
            requireText(symbol, "symbol");
            requireText(source, "source");
            requireText(verificationStatus, "verificationStatus");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            requireConfidence(confidence);
        }
    }

    public record EvidenceDto(int schemaVersion, String projectId, String artifactDigest,
                              String scanId, String evidenceId, String provenanceKind,
                              String source, double confidence, String summary,
                              String observedAt, String toolVersion, String modelVersion,
                              String snapshotRef, String dependencyMode,
                              String verificationStatus) {
        public EvidenceDto(int schemaVersion, String projectId, String artifactDigest,
                           String scanId, String evidenceId, String provenanceKind,
                           String source, double confidence, String summary,
                           String observedAt, String toolVersion, String modelVersion,
                           String snapshotRef, String dependencyMode) {
            this(schemaVersion, projectId, artifactDigest, scanId, evidenceId, provenanceKind,
                    source, confidence, summary, observedAt, toolVersion, modelVersion,
                    snapshotRef, dependencyMode, STATIC_INFERRED);
        }

        public EvidenceDto(int schemaVersion, String projectId, String artifactDigest,
                           String scanId, String evidenceId, String provenanceKind,
                           String source, double confidence, String summary,
                           String observedAt, String toolVersion, String modelVersion,
                           String snapshotRef) {
            this(schemaVersion, projectId, artifactDigest, scanId, evidenceId, provenanceKind,
                    source, confidence, summary, observedAt, toolVersion, modelVersion,
                    snapshotRef, MOCK, STATIC_INFERRED);
        }

        public EvidenceDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(evidenceId, "evidenceId");
            requireText(provenanceKind, "provenanceKind");
            requireText(source, "source");
            requireText(summary, "summary");
            requireText(observedAt, "observedAt");
            requireText(toolVersion, "toolVersion");
            requireText(modelVersion, "modelVersion");
            requireText(snapshotRef, "snapshotRef");
            requireText(dependencyMode, "dependencyMode");
            requireText(verificationStatus, "verificationStatus");
            requireConfidence(confidence);
        }
    }

    public record FindingDto(int schemaVersion, String projectId, String artifactDigest,
                             String scanId, String findingId, String title, String severity,
                             String verificationStatus, String entrypointId, String entry,
                             String sinkId, String sink, String dependency, List<String> dependencyRefs,
                             List<String> evidenceRefs, int evidenceCount, double confidence,
                             String dependencyMode) {
        public FindingDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(findingId, "findingId");
            requireText(title, "title");
            requireText(severity, "severity");
            requireText(verificationStatus, "verificationStatus");
            requireText(entrypointId, "entrypointId");
            requireText(entry, "entry");
            requireText(sinkId, "sinkId");
            requireText(sink, "sink");
            requireText(dependency, "dependency");
            requireText(dependencyMode, "dependencyMode");
            dependencyRefs = List.copyOf(dependencyRefs == null ? List.of() : dependencyRefs);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            if (evidenceCount < 0) throw new IllegalArgumentException("evidenceCount must not be negative");
            requireConfidence(confidence);
        }
    }

    public record PathStepDto(String label, String detail, String kind, String state,
                              List<String> evidenceRefs, String verificationStatus,
                              String provenanceKind, String eventType, Long sequence) {
        public PathStepDto(String label, String detail, String kind, String state,
                           List<String> evidenceRefs) {
            this(label, detail, kind, state, evidenceRefs, STATIC_INFERRED,
                    "INFERENCE", "STATIC_ANALYSIS", null);
        }

        public PathStepDto {
            requireText(label, "label");
            requireText(detail, "detail");
            requireText(kind, "kind");
            requireText(state, "state");
            requireText(verificationStatus, "verificationStatus");
            requireText(provenanceKind, "provenanceKind");
            requireText(eventType, "eventType");
            if (sequence != null && sequence < 0) throw new IllegalArgumentException("sequence cannot be negative");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        }
    }

    public record PathDto(int schemaVersion, String projectId, String artifactDigest,
                          String scanId, String pathId, String entrypointId,
                          String verificationStatus, String dependencyMode,
                          List<String> preconditions, String stopReason,
                          List<String> evidenceRefs, List<PathStepDto> steps,
                          String taskId, Boolean fixtureOnly, String requiredCapability,
                          String dynamicExecutionMode) {
        public PathDto(int schemaVersion, String projectId, String artifactDigest,
                       String scanId, String pathId, String entrypointId,
                       String verificationStatus, String dependencyMode,
                       List<String> preconditions, String stopReason,
                       List<String> evidenceRefs, List<PathStepDto> steps) {
            this(schemaVersion, projectId, artifactDigest, scanId, pathId, entrypointId,
                    verificationStatus, dependencyMode, preconditions, stopReason,
                    evidenceRefs, steps, null, null, null, null);
        }

        public PathDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(pathId, "pathId");
            requireText(entrypointId, "entrypointId");
            requireText(verificationStatus, "verificationStatus");
            requireText(dependencyMode, "dependencyMode");
            requireText(stopReason, "stopReason");
            if (taskId != null) requireText(taskId, "taskId");
            if (requiredCapability != null) requireText(requiredCapability, "requiredCapability");
            if (dynamicExecutionMode != null) requireText(dynamicExecutionMode, "dynamicExecutionMode");
            preconditions = List.copyOf(preconditions == null ? List.of() : preconditions);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            steps = List.copyOf(steps == null ? List.of() : steps);
        }
    }

    public record ScanDto(int schemaVersion, String projectId, String artifactDigest,
                          String scanId, String status, String verificationStatus,
                          String dependencyMode, String createdAt, String completedAt,
                          List<String> evidenceRefs, List<EntryDto> entries,
                          List<DependencyDto> dependencies, List<SinkDto> sinks,
                          List<FindingDto> findings, List<PathDto> paths) {
        public ScanDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(status, "status");
            requireText(verificationStatus, "verificationStatus");
            requireText(dependencyMode, "dependencyMode");
            requireText(createdAt, "createdAt");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            entries = List.copyOf(entries == null ? List.of() : entries);
            dependencies = List.copyOf(dependencies == null ? List.of() : dependencies);
            sinks = List.copyOf(sinks == null ? List.of() : sinks);
            findings = List.copyOf(findings == null ? List.of() : findings);
            paths = List.copyOf(paths == null ? List.of() : paths);
        }
    }

    public record DashboardDto(int schemaVersion, String projectId, String artifactDigest,
                               String scanId, String verificationStatus, String dependencyMode,
                               List<String> evidenceRefs, List<EntryDto> entries,
                               List<FindingDto> findings, List<PathDto> paths,
                               List<PathStepDto> path) {
        public DashboardDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(verificationStatus, "verificationStatus");
            requireText(dependencyMode, "dependencyMode");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            entries = List.copyOf(entries == null ? List.of() : entries);
            findings = List.copyOf(findings == null ? List.of() : findings);
            paths = List.copyOf(paths == null ? List.of() : paths);
            path = List.copyOf(path == null ? List.of() : path);
        }
    }

    public record AttackChainDto(int schemaVersion, String projectId, String artifactDigest,
                                 String scanId, String chainId, String title, double confidence, String verificationStatus,
                                 List<String> findingRefs, List<String> evidenceRefs) {
        public AttackChainDto {
            requireSchema(schemaVersion);
            requireText(projectId, "projectId");
            requireText(artifactDigest, "artifactDigest");
            requireText(scanId, "scanId");
            requireText(chainId, "chainId");
            requireText(title, "title");
            requireText(verificationStatus, "verificationStatus");
            findingRefs = List.copyOf(findingRefs == null ? List.of() : findingRefs);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            requireConfidence(confidence);
        }
    }

    public record ErrorDto(int schemaVersion, String code, String message, String requestId) {
        public ErrorDto {
            requireSchema(schemaVersion);
            requireText(code, "code");
            requireText(message, "message");
            requireText(requestId, "requestId");
        }
    }

    private static void requireSchema(int schemaVersion) {
        if (schemaVersion <= 0) throw new IllegalArgumentException("schemaVersion must be positive");
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) throw new IllegalArgumentException(name + " cannot be blank");
    }

    private static void requireConfidence(double value) {
        if (!Double.isFinite(value) || value < 0 || value > 1) {
            throw new IllegalArgumentException("confidence must be between 0 and 1");
        }
    }
}
