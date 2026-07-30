package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.control.JsonCodec;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Store 辅助类。 */
public final class ControlPlaneAiJobStore {
    private final SQLiteControlPlanePersistence persistence;
    private final ControlPlaneEntityAccess entities;

    public ControlPlaneAiJobStore(SQLiteControlPlanePersistence persistence, ControlPlaneEntityAccess entities) {
        this.persistence = persistence;
        this.entities = entities;
    }

    public void requirePersistentManagement() {
        if (persistence == null) {
            throw new IllegalStateException("management configuration requires SQLite");
        }
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            AiOutputLanguage outputLanguage, boolean authorized, String actorId, String now) {
        entities.requireProject(projectId);
        requirePersistentManagement();
        Objects.requireNonNull(outputLanguage, "outputLanguage");
        if (!authorized) {
            throw new SecurityException("explicit AI job authorization is required");
        }
        String jobId = "ai-job-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        var binding = persistence.findRoleBinding(projectId, requestedRole).orElse(null);
        var provider = binding == null ? null : persistence.findProvider(binding.providerId()).orElse(null);
        ControlPlaneStore.ProjectRecord project = entities.requireProject(projectId);
        ControlPlaneStore.ScanRecord scan = requestedScanId == null
                ? project.latestScanId() == null ? null : entities.scan(project.latestScanId())
                : entities.scan(requestedScanId);
        if (scan != null && !projectId.equals(scan.dto().projectId())) {
            throw new SecurityException("AI job scan does not belong to project");
        }
        String reason = null;
        if (binding == null) {
            reason = "ROLE_BINDING_REQUIRED";
        } else if (provider == null) {
            reason = "PROVIDER_NOT_FOUND";
        } else if (!provider.enabled()) {
            reason = "PROVIDER_DISABLED";
        } else if (!provider.hasCredential()) {
            reason = "PROVIDER_CREDENTIAL_REQUIRED";
        } else if (provider.kind() != ProviderContracts.ProviderKind.OPENAI_CHAT
                && provider.kind() != ProviderContracts.ProviderKind.ANTHROPIC_MESSAGES
                && provider.kind() != ProviderContracts.ProviderKind.OPENAI_COMPATIBLE) {
            reason = "PROVIDER_PROTOCOL_UNSUPPORTED";
        } else if (scan == null) {
            reason = "SCAN_REQUIRED";
        }
        String status = reason == null ? "QUEUED" : "BLOCKED";
        Map<String, Object> stage = new LinkedHashMap<>();
        stage.put("schemaVersion", 1);
        stage.put("role", requestedRole.name());
        stage.put("status", status);
        if (reason != null) {
            stage.put("errorCode", reason);
        }
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
            if (binding.promptZh() != null) {
                policySnapshot.put("promptZh", binding.promptZh());
            }
            if (binding.promptEn() != null) {
                policySnapshot.put("promptEn", binding.promptEn());
            }
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
        SQLiteControlPlanePersistence.AiJobData latest = existing;
        if ("CANCELLED".equals(latest.status()) && !"CANCELLED".equals(status)) {
            return latest;
        }
        SQLiteControlPlanePersistence.AiJobData updated = new SQLiteControlPlanePersistence.AiJobData(
                latest.aiJobId(), latest.workspaceId(), latest.projectId(), latest.scanId(),
                latest.artifactDigest(), latest.role(), latest.providerId(), latest.model(),
                latest.policySnapshotJson(), latest.authorized(), status, stopReason, stagesJson,
                providerRequestId, Math.max(0, elapsedMillis), Math.max(0, rounds),
                toolSummaryJson == null ? "[]" : toolSummaryJson, conclusionJson,
                latest.createdAt(), now);
        persistence.saveAiJob(updated, actorId, action);
        return updated;
    }

    public List<SQLiteControlPlanePersistence.AiJobData> aiJobs(String projectId) {
        if (projectId != null) {
            entities.requireProject(projectId);
        }
        requirePersistentManagement();
        return persistence.listAiJobs(projectId);
    }

    public SQLiteControlPlanePersistence.AiJobData requireAiJob(String jobId) {
        requirePersistentManagement();
        return persistence.findAiJob(jobId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("AI job not found"));
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

    public void assertNoActiveJobsForScan(String projectId, String scanId) {
        if (persistence == null) {
            return;
        }
        for (SQLiteControlPlanePersistence.AiJobData job : persistence.listAiJobs(projectId)) {
            if (scanId.equals(job.scanId())
                    && ("QUEUED".equals(job.status()) || "RUNNING".equals(job.status()))) {
                throw new IllegalStateException("active AI job must be cancelled before scan deletion");
            }
        }
    }
}
