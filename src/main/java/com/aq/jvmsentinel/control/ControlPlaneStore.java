package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.security.RootKeyStore;
import com.aq.jvmsentinel.security.auth.OperatorRole;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Bounded Control Plane store with injectable in-memory or SQLite persistence.
 *
 * <p>The no-argument constructor deliberately remains process-local for unit
 * and fixture tests. Use {@link #sqlite(Path, Path)} for restart-safe local
 * persistence.</p>
 */
public class ControlPlaneStore {
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
    private final SQLiteControlPlanePersistence persistence;
    private final SecretKey rootKey;
    private final ProviderSecretCipher providerCipher;

    public ControlPlaneStore() {
        this.persistence = null;
        this.rootKey = null;
        this.providerCipher = null;
    }

    private ControlPlaneStore(Path databasePath, Path allowedRoot) {
        this.persistence = new SQLiteControlPlanePersistence(databasePath, allowedRoot);
        try {
            Path keyPath = this.persistence.databasePath().getParent()
                    .resolve("security").resolve("provider-root.key");
            this.rootKey = new RootKeyStore(keyPath).loadOrCreate(
                    new RootKeyStore.DeploymentPolicy(true, false)).key();
        } catch (IOException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "provider root key could not be loaded", failure);
        }
        this.providerCipher = new ProviderSecretCipher();
        restore(this.persistence.load());
    }

    public static ControlPlaneStore sqlite(Path databasePath, Path allowedRoot) {
        return new ControlPlaneStore(databasePath, allowedRoot);
    }

    public String persistenceMode() {
        return persistence == null ? "IN_MEMORY_MVP" : "SQLITE";
    }

    public void bootstrapOperator(String token, String now) {
        requirePersistentManagement();
        persistence.bootstrapOperator(token, now);
    }

    public SQLiteControlPlanePersistence.OperatorData authenticateOperator(String token) {
        return persistence == null ? null : persistence.authenticateOperator(token).orElse(null);
    }

    public List<SQLiteControlPlanePersistence.OperatorData> operators() {
        requirePersistentManagement();
        return persistence.listOperators();
    }

    public CreatedOperator createOperator(String username, OperatorRole role, String actorId, String now) {
        requirePersistentManagement();
        validateManagementText(username, "username");
        Objects.requireNonNull(role, "role");
        String id = "operator-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String pat = "vyr_pat_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Arrays.fill(random, (byte) 0);
        SQLiteControlPlanePersistence.OperatorData operator =
                new SQLiteControlPlanePersistence.OperatorData(id, username, role, now, now);
        persistence.createOperator(operator, sha256(pat), actorId);
        return new CreatedOperator(operator, pat);
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                               String actorId, String now) {
        requirePersistentManagement();
        if (persistence.listOperators().stream().noneMatch(value -> value.operatorId().equals(operatorId))) {
            throw new MissingRecordException("operator not found");
        }
        persistence.updateOperator(operatorId, Objects.requireNonNull(role, "role"),
                revokeTokens, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.ProviderData> providers() {
        requirePersistentManagement();
        return persistence.listProviders();
    }

    public SQLiteControlPlanePersistence.ProviderData requireProvider(String providerId) {
        requirePersistentManagement();
        return persistence.findProvider(providerId)
                .orElseThrow(() -> new MissingRecordException("provider not found"));
    }

    public SQLiteControlPlanePersistence.ProviderData saveProvider(
            String providerId, String name, ProviderContracts.ProviderKind kind, String baseUrl,
            String model, boolean enabled, String apiKey, String actorId, String now) {
        requirePersistentManagement();
        validateId(providerId, "providerId");
        validateManagementText(name, "name");
        URI endpoint;
        try {
            endpoint = ProviderContracts.validatedEndpoint(URI.create(baseUrl), kind);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("provider baseUrl is invalid");
        }
        SQLiteControlPlanePersistence.ProviderData existing =
                persistence.findProvider(providerId).orElse(null);
        String createdAt = existing == null ? now : existing.createdAt();
        boolean hasCredential = apiKey != null || existing != null && existing.hasCredential();
        SQLiteControlPlanePersistence.ProviderData provider =
                new SQLiteControlPlanePersistence.ProviderData(providerId, name, kind,
                        endpoint.toString(), model, enabled, createdAt, now, hasCredential);
        SQLiteControlPlanePersistence.StoredSecret secret = null;
        if (apiKey != null) {
            validateManagementText(apiKey, "apiKey");
            SQLiteControlPlanePersistence.StoredSecret existingSecret =
                    persistence.findProviderSecret(providerId).orElse(null);
            long version = existingSecret == null ? 1L
                    : existingSecret.scope().credentialVersion() + 1;
            String credentialId = existingSecret == null
                    ? "provider-api-key-" + sha256(providerId).substring(0, 32)
                    : existingSecret.scope().credentialId();
            ProviderSecretCipher.SecretScope scope = new ProviderSecretCipher.SecretScope(
                    SQLiteControlPlanePersistence.LOCAL_WORKSPACE, providerId,
                    credentialId, version);
            byte[] plaintext = apiKey.getBytes(StandardCharsets.UTF_8);
            try {
                secret = new SQLiteControlPlanePersistence.StoredSecret(
                        scope, providerCipher.encrypt(rootKey, scope, plaintext));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
        persistence.saveProvider(provider, secret, actorId);
        return requireProvider(providerId);
    }

    public void verifyProviderCredential(String providerId) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        Arrays.fill(plaintext, (byte) 0);
    }

    /**
     * Decrypts a provider credential only for the duration of the supplied operation.
     * The operation must not retain the array; this method clears it on every exit path.
     */
    public <T> T withProviderCredential(String providerId, Function<byte[], T> operation) {
        requirePersistentManagement();
        Objects.requireNonNull(operation, "operation");
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        try {
            return operation.apply(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        requireProvider(providerId);
        persistence.deleteProvider(providerId, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.RoleBindingData> roleBindings(String projectId) {
        requireProject(projectId);
        requirePersistentManagement();
        return persistence.listRoleBindings(projectId);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model, String actorId, String now) {
        requireProject(projectId);
        requireProvider(providerId);
        validateManagementText(model, "model");
        SQLiteControlPlanePersistence.RoleBindingData binding =
                new SQLiteControlPlanePersistence.RoleBindingData(projectId, role, providerId, model, now);
        persistence.saveRoleBinding(binding, actorId);
        return binding;
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        requireProject(projectId);
        if (persistence.findRoleBinding(projectId, role).isEmpty()) {
            throw new MissingRecordException("role assignment not found");
        }
        persistence.deleteRoleBinding(projectId, role, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, boolean authorized, String actorId, String now) {
        return createAiJob(projectId, requestedRole, null, AiOutputLanguage.ZH_CN,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            boolean authorized, String actorId, String now) {
        return createAiJob(projectId, requestedRole, requestedScanId, AiOutputLanguage.ZH_CN,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            AiOutputLanguage outputLanguage, boolean authorized, String actorId, String now) {
        requireProject(projectId);
        requirePersistentManagement();
        Objects.requireNonNull(outputLanguage, "outputLanguage");
        if (!authorized) throw new SecurityException("explicit AI job authorization is required");
        String jobId = "ai-job-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        var binding = persistence.findRoleBinding(projectId, requestedRole).orElse(null);
        var provider = binding == null ? null : persistence.findProvider(binding.providerId()).orElse(null);
        ProjectRecord project = requireProject(projectId);
        ScanRecord scan = requestedScanId == null
                ? project.latestScanId() == null ? null : scan(project.latestScanId())
                : scan(requestedScanId);
        if (scan != null && !projectId.equals(scan.dto().projectId())) {
            throw new SecurityException("AI job scan does not belong to project");
        }
        String reason = null;
        if (binding == null) reason = "ROLE_BINDING_REQUIRED";
        else if (provider == null) reason = "PROVIDER_NOT_FOUND";
        else if (!provider.enabled()) reason = "PROVIDER_DISABLED";
        else if (!provider.hasCredential()) reason = "PROVIDER_CREDENTIAL_REQUIRED";
        else if (provider.kind() != ProviderContracts.ProviderKind.OPENAI_CHAT
                && provider.kind() != ProviderContracts.ProviderKind.ANTHROPIC_MESSAGES
                && provider.kind() != ProviderContracts.ProviderKind.OPENAI_COMPATIBLE) {
            reason = "PROVIDER_PROTOCOL_UNSUPPORTED";
        } else if (scan == null) reason = "SCAN_REQUIRED";
        String status = reason == null ? "QUEUED" : "BLOCKED";
        Map<String, Object> stage = new LinkedHashMap<>();
        stage.put("schemaVersion", 1);
        stage.put("role", requestedRole.name());
        stage.put("status", status);
        if (reason != null) stage.put("errorCode", reason);
        if (binding != null) {
            stage.put("providerId", binding.providerId());
            stage.put("model", binding.model());
        }
        List<Map<String, Object>> stages = List.of(stage);
        String stagesJson = JsonCodec.stringify(stages);
        Map<String, Object> policySnapshot = new LinkedHashMap<>();
        policySnapshot.put("schemaVersion", 1);
        policySnapshot.put("maxRounds", 5);
        policySnapshot.put("maxToolCalls", 16);
        policySnapshot.put("maxOutputTokens", 2048);
        policySnapshot.put("maxResponseBytes", 1_048_576);
        policySnapshot.put("requestTimeoutSeconds", 120);
        policySnapshot.put("parallelToolCalls", false);
        policySnapshot.put("outputLanguage", outputLanguage.name());
        policySnapshot.put("outputFormat", "MARKDOWN");
        if (binding != null) {
            policySnapshot.put("providerId", binding.providerId());
            policySnapshot.put("model", binding.model());
            policySnapshot.put("roleBindingUpdatedAt", binding.updatedAt());
        }
        if (provider != null) {
            policySnapshot.put("providerKind", provider.kind().name());
            policySnapshot.put("providerBaseUrl", provider.baseUrl());
            policySnapshot.put("providerConfigurationUpdatedAt", provider.updatedAt());
        }
        String policy = JsonCodec.stringify(policySnapshot);
        SQLiteControlPlanePersistence.AiJobData job = new SQLiteControlPlanePersistence.AiJobData(
                jobId, SQLiteControlPlanePersistence.LOCAL_WORKSPACE, projectId,
                scan == null ? null : scan.dto().scanId(),
                scan == null ? null : scan.dto().artifactDigest(), requestedRole,
                binding == null ? null : binding.providerId(), binding == null ? null : binding.model(),
                policy, true, status, reason == null ? "QUEUED" : reason, stagesJson,
                null, 0, 0, "[]", null, now, now);
        persistence.saveAiJob(job, actorId, status.equals("QUEUED") ? "ai-job.queued" : "ai-job.blocked");
        return job;
    }

    public SQLiteControlPlanePersistence.AiJobData updateAiJob(
            SQLiteControlPlanePersistence.AiJobData existing, String status, String stopReason,
            String stagesJson, String providerRequestId, long elapsedMillis, int rounds,
            String toolSummaryJson, String conclusionJson, String actorId, String action, String now) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.AiJobData updated = new SQLiteControlPlanePersistence.AiJobData(
                existing.aiJobId(), existing.workspaceId(), existing.projectId(), existing.scanId(),
                existing.artifactDigest(), existing.role(), existing.providerId(), existing.model(),
                existing.policySnapshotJson(), existing.authorized(), status, stopReason, stagesJson,
                providerRequestId, Math.max(0, elapsedMillis), Math.max(0, rounds),
                toolSummaryJson == null ? "[]" : toolSummaryJson, conclusionJson,
                existing.createdAt(), now);
        persistence.saveAiJob(updated, actorId, action);
        return updated;
    }

    public List<SQLiteControlPlanePersistence.AiJobData> aiJobs(String projectId) {
        if (projectId != null) requireProject(projectId);
        requirePersistentManagement();
        return persistence.listAiJobs(projectId);
    }

    public SQLiteControlPlanePersistence.AiJobData requireAiJob(String jobId) {
        requirePersistentManagement();
        return persistence.findAiJob(jobId).orElseThrow(() -> new MissingRecordException("AI job not found"));
    }

    public SQLiteControlPlanePersistence.AiJobEventData appendAiJobEvent(
            SQLiteControlPlanePersistence.AiJobEventData event) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.AiJobData job = requireAiJob(event.aiJobId());
        if (!job.workspaceId().equals(event.workspaceId())
                || !job.projectId().equals(event.projectId())) {
            throw new IllegalArgumentException("AI job event scope mismatch");
        }
        return persistence.appendAiJobEvent(event);
    }

    public List<SQLiteControlPlanePersistence.AiJobEventData> aiJobEvents(String jobId) {
        requireAiJob(jobId);
        return persistence.listAiJobEvents(jobId);
    }

    public SQLiteControlPlanePersistence.AiJobData cancelAiJob(String jobId, String actorId, String now) {
        SQLiteControlPlanePersistence.AiJobData existing = requireAiJob(jobId);
        if ("COMPLETED".equals(existing.status()) || "FAILED".equals(existing.status())
                || "CANCELLED".equals(existing.status()) || "BLOCKED".equals(existing.status())) {
            return existing;
        }
        return updateAiJob(existing, "CANCELLED", "USER_CANCELLED", existing.stagesJson(),
                existing.providerRequestId(), existing.elapsedMillis(), existing.rounds(),
                existing.toolSummaryJson(), null, actorId, "ai-job.cancel", now);
    }

    public void deleteAiJob(String jobId, String actorId, String now) {
        SQLiteControlPlanePersistence.AiJobData existing = requireAiJob(jobId);
        if ("QUEUED".equals(existing.status()) || "RUNNING".equals(existing.status())) {
            throw new IllegalStateException("active AI job must be cancelled before deletion");
        }
        persistence.deleteAiJob(existing, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.AuditData> auditEvents(String projectId) {
        requirePersistentManagement();
        if (projectId != null) requireProject(projectId);
        return persistence.listAudit(projectId);
    }

    public void auditChange(String projectId, String actorId, String action,
                            String targetType, String targetId, String detailsJson, String now) {
        if (persistence != null) {
            persistence.recordAudit(projectId, actorId, action, targetType, targetId, detailsJson, now);
        }
    }

    private void requirePersistentManagement() {
        if (persistence == null) throw new IllegalStateException("management configuration requires SQLite");
    }

    private static void validateManagementText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 4096
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    public synchronized ProjectRecord createProject(String requestedId, String requestedName, String createdAt,
                                                    String actorId) {
        String id = requestedId == null || requestedId.isBlank()
                ? "project-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                : requestedId;
        String name = requestedName == null || requestedName.isBlank() ? id : requestedName;
        validateId(id, "projectId");
        if (createdAt == null || createdAt.isBlank()) throw new IllegalArgumentException("createdAt is required");
        if (projects.size() >= MAX_PROJECTS) throw new StoreLimitException("project limit reached");
        ProjectRecord candidate = new ProjectRecord(id, name, "ACTIVE", createdAt, createdAt, null);
        if (projects.containsKey(id)) throw new DuplicateRecordException("project already exists");
        if (persistence != null) persistence.insertProject(id, name, candidate.status, createdAt, createdAt, actorId);
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
        ProjectRecord project = projectId == null ? null : projects.get(projectId);
        return project == null || project.deleted() ? null : project;
    }

    public List<ProjectRecord> projects() {
        return projects.values().stream().filter(project -> !project.deleted())
                .sorted(Comparator.comparing(ProjectRecord::createdAt).thenComparing(ProjectRecord::projectId))
                .toList();
    }

    public synchronized ProjectRecord updateProject(String projectId, String requestedName,
                                                    String requestedStatus, String updatedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        String name = requestedName == null ? project.name : requestedName;
        String status = requestedStatus == null ? project.status : requestedStatus.toUpperCase(java.util.Locale.ROOT);
        if (name.isBlank() || name.length() > 512) throw new IllegalArgumentException("name is invalid");
        if (!status.equals("ACTIVE") && !status.equals("ARCHIVED")) {
            throw new IllegalArgumentException("status must be ACTIVE or ARCHIVED");
        }
        if (updatedAt == null || updatedAt.isBlank()) throw new IllegalArgumentException("updatedAt is required");
        if (persistence != null) persistence.updateProject(projectId, name, status, updatedAt, actorId);
        project.name = name;
        project.status = status;
        project.updatedAt = updatedAt;
        return project;
    }

    public synchronized void softDeleteProject(String projectId, String deletedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        if (deletedAt == null || deletedAt.isBlank()) throw new IllegalArgumentException("deletedAt is required");
        if (persistence != null) persistence.softDeleteProject(projectId, deletedAt, actorId);
        project.status = "DELETED";
        project.updatedAt = deletedAt;
        project.deletedAt = deletedAt;
    }

    public synchronized void registerArtifact(ProjectRecord project, ArtifactDescriptor descriptor,
                                              String actorId) {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(descriptor, "descriptor");
        synchronized (project) {
            if (project.artifacts.size() >= MAX_ARTIFACTS_PER_PROJECT
                    && !project.artifacts.containsKey(descriptor.sha256())) {
                throw new StoreLimitException("artifact limit reached for project");
            }
            if (project.deleted()) throw new MissingRecordException("project not found");
            if (persistence != null) persistence.insertArtifact(project.projectId, descriptor, actorId);
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

    public synchronized void saveScan(ScanRecord record, String actorId) {
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
        if (persistence != null) persistence.insertScan(record, actorId);
        ScanRecord prior = scans.putIfAbsent(record.dto().scanId(), record);
        if (prior != null) throw new DuplicateRecordException("scan already exists");
        synchronized (project) { project.latestScanId = record.dto().scanId(); }
        for (ApiDtos.EvidenceDto item : record.evidence().values()) evidence.putIfAbsent(item.evidenceId(), item);
        for (ApiDtos.FindingDto item : record.findings()) findings.putIfAbsent(item.findingId(), item);
        for (ApiDtos.AttackChainDto item : record.chains()) chains.putIfAbsent(item.chainId(), item);
    }

    public List<ScanRecord> scansForProject(String projectId) {
        requireProject(projectId);
        return scans.values().stream()
                .filter(record -> record.dto().projectId().equals(projectId))
                .sorted(Comparator.comparing((ScanRecord record) -> record.dto().createdAt()).reversed()
                        .thenComparing(record -> record.dto().scanId()))
                .toList();
    }

    public ScanRecord scan(String scanId) {
        ScanRecord result = scanId == null ? null : scans.get(scanId);
        return result == null || project(result.dto().projectId()) == null ? null : result;
    }

    public ScanRecord requireScan(String scanId) {
        ScanRecord result = scan(scanId);
        if (result == null) throw new MissingRecordException("scan not found");
        return result;
    }

    public ApiDtos.FindingDto finding(String findingId) {
        ApiDtos.FindingDto result = findingId == null ? null : findings.get(findingId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    public ApiDtos.EvidenceDto evidence(String evidenceId) {
        ApiDtos.EvidenceDto result = evidenceId == null ? null : evidence.get(evidenceId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    public List<ApiDtos.AttackChainDto> attackChains(String projectId) {
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : chains.values()) {
            if (project(chain.projectId()) != null
                    && (projectId == null || projectId.equals(chain.projectId()))) result.add(chain);
        }
        return List.copyOf(result);
    }

    private void restore(SQLiteControlPlanePersistence.Snapshot snapshot) {
        for (SQLiteControlPlanePersistence.ProjectData item : snapshot.projects()) {
            projects.put(item.projectId(), new ProjectRecord(item.projectId(), item.name(), item.status(),
                    item.createdAt(), item.updatedAt(), item.deletedAt()));
        }
        for (SQLiteControlPlanePersistence.ArtifactData item : snapshot.artifacts()) {
            ProjectRecord project = projects.get(item.projectId());
            if (project == null) throw new SQLiteControlPlanePersistence.PersistenceException(
                    "artifact references a missing project");
            project.artifacts.put(item.descriptor().sha256(), item.descriptor());
        }
        for (ScanRecord record : snapshot.scans()) {
            ProjectRecord project = projects.get(record.dto().projectId());
            if (project == null || !project.artifacts.containsKey(record.dto().artifactDigest())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "scan references missing project or artifact");
            }
            scans.put(record.dto().scanId(), record);
            project.latestScanId = record.dto().scanId();
            for (ApiDtos.EvidenceDto item : record.evidence().values()) evidence.put(item.evidenceId(), item);
            for (ApiDtos.FindingDto item : record.findings()) findings.put(item.findingId(), item);
            for (ApiDtos.AttackChainDto item : record.chains()) chains.put(item.chainId(), item);
        }
    }

    public static final class ProjectRecord {
        private final String projectId;
        private volatile String name;
        private final String createdAt;
        private volatile String status;
        private volatile String updatedAt;
        private volatile String deletedAt;
        private final Map<String, ArtifactDescriptor> artifacts = new LinkedHashMap<>();
        private volatile String latestScanId;

        private ProjectRecord(String projectId, String name, String status, String createdAt,
                              String updatedAt, String deletedAt) {
            this.projectId = projectId;
            this.name = name;
            this.status = status;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
            this.deletedAt = deletedAt;
        }

        public String projectId() { return projectId; }
        public String name() { return name; }
        public String status() { return status; }
        public String createdAt() { return createdAt; }
        public String updatedAt() { return updatedAt; }
        public String deletedAt() { return deletedAt; }
        public boolean deleted() { return deletedAt != null; }
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

    public record CreatedOperator(SQLiteControlPlanePersistence.OperatorData operator, String personalAccessToken) { }

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
