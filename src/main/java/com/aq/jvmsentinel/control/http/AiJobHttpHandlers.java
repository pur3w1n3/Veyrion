package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.http.ControlPlaneHttpLimits;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：AiJob 域。 */
final class AiJobHttpHandlers extends ControlPlaneHandlerSupport {
    private final OperatorProviderHttpHandlers operators;

    AiJobHttpHandlers(ControlPlaneHandlerHost host, OperatorProviderHttpHandlers operators) {
        super(host);
        this.operators = operators;
    }

    public void listRoleAssignments(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var binding : host.store.roleBindings(projectId)) items.add(roleBindingMap(binding));
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("roleAssignments", items));
    }
    public void sendRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        var binding = host.store.roleBindings(projectId).stream().filter(value -> value.role() == role)
                .findFirst().orElseThrow(() -> new ControlPlaneStore.MissingRecordException(
                        "role assignment not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, roleBindingMap(binding));
    }
    public void saveRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String providerId = ControlPlaneHttpSupport.optionalText(body, "providerId", null);
        if (providerId == null) throw new ControlPlaneHttpSupport.ApiException(400, "PROVIDER_REQUIRED", "providerId is required");
        var provider = host.store.requireProvider(providerId);
        String model = ControlPlaneHttpSupport.optionalText(body, "model", provider.model());
        if (model == null) throw new ControlPlaneHttpSupport.ApiException(400, "MODEL_REQUIRED", "model is required");
        String promptZh = ControlPlaneHttpSupport.optionalPrompt(body, "promptZh");
        String promptEn = ControlPlaneHttpSupport.optionalPrompt(body, "promptEn");
        ControlPlaneHttpSupport.sendJson(exchange, 200, roleBindingMap(host.store.saveRoleBinding(projectId, role, providerId, model,
                promptZh, promptEn, operators.actor(exchange).operatorId(), Instant.now(host.clock).toString())));
    }
    public void deleteRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        host.store.deleteRoleBinding(projectId, role, operators.actor(exchange).operatorId(), Instant.now(host.clock).toString());
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    public void listAiJobs(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var job : host.store.aiJobs(projectId)) items.add(aiJobMap(job));
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("aiJobs", items));
    }
    public void createAiJob(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("role", "scanId", "authorized", "outputLanguage").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "AI_JOB_FIELD_REJECTED",
                        "AI job body only accepts role, scanId, authorized and outputLanguage");
            }
        }
        AgentRole role = operators.role(ControlPlaneHttpSupport.optionalText(body, "role", null));
        String scanId = ControlPlaneHttpSupport.optionalText(body, "scanId", null);
        AiOutputLanguage outputLanguage = outputLanguage(ControlPlaneHttpSupport.optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit AI job authorization is required");
        }
        String operatorId = operators.actor(exchange).operatorId();
        var job = host.store.createAiJob(projectId, role, scanId, outputLanguage, true, operatorId,
                Instant.now(host.clock).toString());
        host.aiJobOrchestrator.submit(job, operatorId);
        ControlPlaneHttpSupport.sendJson(exchange, 202, aiJobMap(job));
    }
    public void sendAiJob(HttpExchange exchange, String jobId) throws IOException {
        ControlPlaneHttpSupport.sendJson(exchange, 200, aiJobMap(host.store.requireAiJob(jobId)));
    }
    public void listAiJobEvents(HttpExchange exchange, String jobId) throws IOException {
        var job = host.store.requireAiJob(jobId);
        var events = host.store.aiJobEvents(jobId);
        if (events.size() > ControlPlaneHttpLimits.MAX_AI_JOB_EVENTS) {
            throw new ControlPlaneHttpSupport.ApiException(500, "AI_JOB_EVENT_BOUND_INVALID",
                    "stored AI job event history exceeds its fixed bound");
        }
        List<Object> items = new ArrayList<>();
        long expectedSequence = 1;
        for (var event : events) {
            if (!job.aiJobId().equals(event.aiJobId())
                    || !job.workspaceId().equals(event.workspaceId())
                    || !job.projectId().equals(event.projectId())) {
                throw new ControlPlaneHttpSupport.ApiException(500, "AI_JOB_EVENT_SCOPE_INVALID",
                        "stored AI job event scope does not match its job");
            }
            if (event.sequence() != expectedSequence++) {
                throw new ControlPlaneHttpSupport.ApiException(500, "AI_JOB_EVENT_ORDER_INVALID",
                        "stored AI job events are not contiguous and ordered");
            }
            items.add(aiJobEventMap(event, job.stopReason()));
        }
        Map<String, Object> response = stringEnvelope("aiJobEvents", items);
        response.put("aiJobId", job.aiJobId());
        response.put("projectId", job.projectId());
        ControlPlaneHttpSupport.sendJson(exchange, 200, response);
    }
    public void updateAiJob(HttpExchange exchange, String jobId) throws IOException {
        String action = ControlPlaneHttpSupport.optionalText(ControlPlaneHttpSupport.readObject(exchange), "action", null);
        if ("retry".equals(action)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "RETRY_REQUIRES_NEW_AUTHORIZATION",
                    "create a new explicitly authorized AI job");
        }
        if (!"cancel".equals(action)) throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ACTION", "action must be cancel or retry");
        String operatorId = operators.actor(exchange).operatorId();
        var cancelled = host.store.cancelAiJob(jobId, operatorId, Instant.now(host.clock).toString());
        host.aiJobOrchestrator.cancel(jobId);
        AuditPipelineCoordinator.Cursor cursor = cancelled.scanId() == null
                ? null : host.auditPipeline.cursor(cancelled.scanId());
        if (cursor != null && jobId.equals(cursor.expectedJobId())) {
            host.store.auditChange(cancelled.projectId(), operatorId, "audit-pipeline.cancel", "ai-job", jobId,
                    "{\"reason\":\"USER_CANCELLED\",\"pipelineRunId\":\"" + cursor.arm().pipelineRunId()
                            + "\",\"stageAttemptId\":\"" + cursor.stageAttemptId()
                            + "\",\"stage\":\"" + cursor.stage().name()
                            + "\",\"scanId\":\"" + cancelled.scanId() + "\"}",
                    Instant.now(host.clock).toString());
        }
        // 终态 cancel 必须到达 pipeline，即使 orchestrator 从未启动 job。
        host.auditPipeline.onAiJobFinished(cancelled);
        ControlPlaneHttpSupport.sendJson(exchange, 200, aiJobMap(cancelled));
    }
    public void deleteAiJob(HttpExchange exchange, String jobId) throws IOException {
        var existing = host.store.requireAiJob(jobId);
        if ("QUEUED".equals(existing.status()) || "RUNNING".equals(existing.status())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "AI_JOB_ACTIVE",
                    "cancel the AI job before deletion");
        }
        host.store.deleteAiJob(jobId, operators.actor(exchange).operatorId(), Instant.now(host.clock).toString());
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    static AiOutputLanguage outputLanguage(String value) {
        try {
            return AiOutputLanguage.parse(value);
        } catch (IllegalArgumentException invalid) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_OUTPUT_LANGUAGE",
                    "outputLanguage must be ZH_CN or EN");
        }
    }
    static Map<String, Object> roleBindingMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.RoleBindingData binding) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 2);
        result.put("projectId", binding.projectId());
        result.put("role", binding.role().name());
        result.put("providerId", binding.providerId());
        result.put("model", binding.model());
        result.put("promptZh", binding.promptZh());
        result.put("promptEn", binding.promptEn());
        result.put("updatedAt", binding.updatedAt());
        return result;
    }
    static Map<String, Object> aiJobMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData job) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("aiJobId", job.aiJobId());
        result.put("workspaceId", job.workspaceId());
        result.put("projectId", job.projectId());
        if (job.scanId() != null) result.put("scanId", job.scanId());
        if (job.artifactDigest() != null) result.put("artifactDigest", job.artifactDigest());
        result.put("role", job.role().name());
        if (job.providerId() != null) result.put("providerId", job.providerId());
        if (job.model() != null) result.put("model", job.model());
        result.put("authorized", job.authorized());
        result.put("status", job.status());
        result.put("stopReason", job.stopReason());
        if (!"COMPLETED".equals(job.status())) result.put("errorCode", job.stopReason());
        result.put("stages", JsonCodec.parse(job.stagesJson()));
        Object policySnapshot = JsonCodec.parse(job.policySnapshotJson());
        result.put("policySnapshot", policySnapshot);
        if (policySnapshot instanceof Map<?, ?> policy
                && policy.get("outputLanguage") instanceof String language
                && ("ZH_CN".equals(language) || "EN".equals(language))) {
            result.put("outputLanguage", language);
        }
        if (job.providerRequestId() != null) result.put("providerRequestId", job.providerRequestId());
        result.put("elapsedMillis", job.elapsedMillis());
        result.put("rounds", job.rounds());
        result.put("toolSummary", JsonCodec.parse(job.toolSummaryJson()));
        if (job.conclusionJson() != null) result.put("conclusion", JsonCodec.parse(job.conclusionJson()));
        result.put("createdAt", job.createdAt());
        result.put("updatedAt", job.updatedAt());
        result.put("verificationStatus", job.conclusionJson() == null ? "UNREACHED" : "INFERENCE");
        return result;
    }
    static Map<String, Object> aiJobEventMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobEventData event,
            String jobStopReason) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("aiJobId", event.aiJobId());
        result.put("sequence", event.sequence());
        result.put("workspaceId", event.workspaceId());
        result.put("projectId", event.projectId());
        result.put("stage", event.stage());
        result.put("status", event.status());
        if (event.providerRequestSummary() != null) {
            result.put("providerRequestSummary", event.providerRequestSummary());
        }
        if (event.providerResultSummary() != null) {
            result.put("providerResultSummary", event.providerResultSummary());
        }
        if (event.toolCallName() != null) result.put("toolCallName", event.toolCallName());
        if (event.toolArgumentsSummary() != null) {
            result.put("toolArgumentsSummary", event.toolArgumentsSummary());
        }
        if (event.toolResultStatus() != null) {
            result.put("toolResultStatus", event.toolResultStatus());
        }
        if (event.modelInferenceSummary() != null) {
            result.put("modelInferenceSummary", event.modelInferenceSummary());
        }
        if (event.failureDiagnostic() != null) {
            result.put("failureDiagnostic", event.failureDiagnostic());
        } else if ("FAILED".equals(event.status())) {
            String failureCode = jobStopReason != null
                    && jobStopReason.matches("[A-Z0-9_]{1,64}")
                    ? jobStopReason : "AI_JOB_FAILED";
            result.put("failureDiagnostic",
                    "Failure code: " + failureCode + "; detailed provider output was not retained");
        }
        result.put("createdAt", event.createdAt());
        return result;
    }
    static Map<String, Object> auditMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AuditData event) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("auditEventId", event.auditEventId());
        if (event.projectId() != null) result.put("projectId", event.projectId());
        result.put("operatorId", event.operatorId());
        result.put("action", event.action());
        result.put("targetType", event.targetType());
        result.put("targetId", event.targetId());
        result.put("outcome", event.outcome());
        result.put("details", JsonCodec.parse(event.detailsJson()));
        result.put("createdAt", event.createdAt());
        return result;
    }
}
