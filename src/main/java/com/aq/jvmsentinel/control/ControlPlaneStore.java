package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bounded-scope in-memory store for the MVP control plane.
 *
 * <p>The store deliberately keeps immutable DTO snapshots.  It is not a
 * persistence layer: restarting the process removes all projects, scans and
 * evidence.  The API exposes this fact through the {@code persistenceMode}
 * field on the health endpoint and documentation.</p>
 */
public final class ControlPlaneStore {
    private static final int MAX_PROJECTS = 10_000;
    private static final int MAX_ARTIFACTS_PER_PROJECT = 1_000;
    private static final int MAX_SCANS = 20_000;
    private static final int MAX_EVIDENCE = 100_000;
    private static final int MAX_FINDINGS = 100_000;

    private final Map<String, ProjectRecord> projects = new ConcurrentHashMap<>();
    private final Map<String, ScanRecord> scans = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.FindingDto> findings = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.EvidenceDto> evidence = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.AttackChainDto> chains = new ConcurrentHashMap<>();

    public ProjectRecord createProject(String requestedId, String requestedName, String createdAt) {
        String id = requestedId == null || requestedId.isBlank()
                ? "project-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                : requestedId;
        String name = requestedName == null || requestedName.isBlank() ? id : requestedName;
        validateId(id, "projectId");
        if (createdAt == null || createdAt.isBlank()) throw new IllegalArgumentException("createdAt is required");
        if (projects.size() >= MAX_PROJECTS) throw new StoreLimitException("project limit reached");
        ProjectRecord candidate = new ProjectRecord(id, name, createdAt);
        ProjectRecord existing = projects.putIfAbsent(id, candidate);
        if (existing != null) throw new DuplicateRecordException("project already exists");
        return candidate;
    }

    public ProjectRecord requireProject(String projectId) {
        ProjectRecord result = project(projectId);
        if (result == null) throw new MissingRecordException("project not found");
        return result;
    }

    public ProjectRecord project(String projectId) {
        return projectId == null ? null : projects.get(projectId);
    }

    public List<ProjectRecord> projects() {
        return List.copyOf(projects.values());
    }

    public void registerArtifact(ProjectRecord project, ArtifactDescriptor descriptor) {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(descriptor, "descriptor");
        synchronized (project) {
            if (project.artifacts.size() >= MAX_ARTIFACTS_PER_PROJECT
                    && !project.artifacts.containsKey(descriptor.sha256())) {
                throw new StoreLimitException("artifact limit reached for project");
            }
            project.artifacts.put(descriptor.sha256(), descriptor);
        }
    }

    public ArtifactDescriptor artifact(ProjectRecord project, String digestOrId) {
        if (project == null || digestOrId == null) return null;
        synchronized (project) {
            ArtifactDescriptor byDigest = project.artifacts.get(digestOrId);
            if (byDigest != null) return byDigest;
            for (ArtifactDescriptor descriptor : project.artifacts.values()) {
                if (descriptor.artifactId().equals(digestOrId)) return descriptor;
            }
            return null;
        }
    }

    public List<ArtifactDescriptor> artifacts(ProjectRecord project) {
        if (project == null) return List.of();
        synchronized (project) { return List.copyOf(project.artifacts.values()); }
    }

    public void saveScan(ScanRecord record) {
        Objects.requireNonNull(record, "record");
        ProjectRecord project = requireProject(record.dto().projectId());
        if (scans.size() >= MAX_SCANS && !scans.containsKey(record.dto().scanId())) {
            throw new StoreLimitException("scan limit reached");
        }
        if (scans.containsKey(record.dto().scanId())) throw new DuplicateRecordException("scan already exists");
        // Validate all global limits before publishing any part of the
        // snapshot.  A failed save must not leave a scan pointer or orphaned
        // evidence behind.
        int newEvidence = 0;
        for (ApiDtos.EvidenceDto item : record.evidence().values()) {
            if (!evidence.containsKey(item.evidenceId())) newEvidence++;
        }
        if (evidence.size() + newEvidence > MAX_EVIDENCE) throw new StoreLimitException("evidence limit reached");
        int newFindings = 0;
        for (ApiDtos.FindingDto item : record.findings()) {
            if (!findings.containsKey(item.findingId())) newFindings++;
        }
        if (findings.size() + newFindings > MAX_FINDINGS) throw new StoreLimitException("finding limit reached");
        ScanRecord prior = scans.putIfAbsent(record.dto().scanId(), record);
        if (prior != null) throw new DuplicateRecordException("scan already exists");
        synchronized (project) { project.latestScanId = record.dto().scanId(); }
        for (ApiDtos.EvidenceDto item : record.evidence().values()) evidence.putIfAbsent(item.evidenceId(), item);
        for (ApiDtos.FindingDto item : record.findings()) findings.putIfAbsent(item.findingId(), item);
        for (ApiDtos.AttackChainDto item : record.chains()) chains.putIfAbsent(item.chainId(), item);
    }

    public ScanRecord scan(String scanId) { return scanId == null ? null : scans.get(scanId); }

    public ScanRecord requireScan(String scanId) {
        ScanRecord result = scan(scanId);
        if (result == null) throw new MissingRecordException("scan not found");
        return result;
    }

    public ApiDtos.FindingDto finding(String findingId) { return findingId == null ? null : findings.get(findingId); }

    public ApiDtos.EvidenceDto evidence(String evidenceId) { return evidenceId == null ? null : evidence.get(evidenceId); }

    public List<ApiDtos.AttackChainDto> attackChains(String projectId) {
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : chains.values()) {
            if (projectId == null || projectId.equals(chain.projectId())) result.add(chain);
        }
        return List.copyOf(result);
    }

    public static final class ProjectRecord {
        private final String projectId;
        private final String name;
        private final String createdAt;
        private final Map<String, ArtifactDescriptor> artifacts = new LinkedHashMap<>();
        private volatile String latestScanId;

        private ProjectRecord(String projectId, String name, String createdAt) {
            this.projectId = projectId;
            this.name = name;
            this.createdAt = createdAt;
        }

        public String projectId() { return projectId; }
        public String name() { return name; }
        public String createdAt() { return createdAt; }
        public String latestScanId() { return latestScanId; }
    }

    /** Immutable scan snapshot plus its evidence and correlation records. */
    public record ScanRecord(ApiDtos.ScanDto dto, Map<String, ApiDtos.EvidenceDto> evidence,
                             List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains) {
        public ScanRecord {
            Objects.requireNonNull(dto, "dto");
            Map<String, ApiDtos.EvidenceDto> copiedEvidence = new LinkedHashMap<>();
            if (evidence != null) copiedEvidence.putAll(evidence);
            evidence = Collections.unmodifiableMap(copiedEvidence);
            findings = List.copyOf(findings == null ? List.of() : findings);
            chains = List.copyOf(chains == null ? List.of() : chains);
        }
    }

    public static final class MissingRecordException extends RuntimeException {
        public MissingRecordException(String message) { super(message); }
    }

    public static final class DuplicateRecordException extends RuntimeException {
        public DuplicateRecordException(String message) { super(message); }
    }

    public static final class StoreLimitException extends RuntimeException {
        public StoreLimitException(String message) { super(message); }
    }

    static void validateId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
    }
}
