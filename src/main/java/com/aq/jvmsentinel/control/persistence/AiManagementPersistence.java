package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.security.ProviderSecretCipher.EncryptedSecret;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretScope;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 操作员、Provider、角色绑定、AI 作业与审计事件的持久化。
 */
final class AiManagementPersistence {
    private static final int MAX_AI_JOB_EVENTS = 128;

    private final PersistenceSupport support;

    AiManagementPersistence(PersistenceSupport support) {
        this.support = support;
    }

    void bootstrapOperator(String token, String now) {
        Objects.requireNonNull(token, "token");
        try (Connection connection = support.open()) {
            connection.setAutoCommit(false);
            try {
                int count;
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("SELECT count(*) FROM operators")) {
                    count = rows.next() ? rows.getInt(1) : 0;
                }
                if (count == 0) {
                    PersistenceSupport.update(connection,
                            "INSERT INTO operators(operator_id,username,role,created_at,updated_at)"
                                    + " VALUES(?,?,?,?,?)",
                            "local-admin", "local-admin", OperatorRole.ADMINISTRATOR.name(), now, now);
                    PersistenceSupport.update(connection,
                            "INSERT INTO operator_tokens(token_id,operator_id,token_hash,created_at)"
                                    + " VALUES(?,?,?,?)",
                            "bootstrap-token", "local-admin", PersistenceSupport.sha256(token), now);
                    PersistenceSupport.audit(connection, null, "local-admin", "operator.bootstrap",
                            "operator", "local-admin", "{}", now);
                } else {
                    try (PreparedStatement administrator = connection.prepareStatement(
                            "SELECT role FROM operators WHERE operator_id='local-admin'")) {
                        try (ResultSet rows = administrator.executeQuery()) {
                            if (!rows.next() || !OperatorRole.ADMINISTRATOR.name().equals(rows.getString(1))) {
                                throw new SQLiteControlPlanePersistence.PersistenceException(
                                        "persistent local administrator is missing or no longer an administrator");
                            }
                        }
                    }
                    PersistenceSupport.update(connection,
                            "UPDATE operator_tokens SET token_hash=?,created_at=?,revoked_at=NULL"
                                    + " WHERE token_id='bootstrap-token' AND operator_id='local-admin'",
                            PersistenceSupport.sha256(token), now);
                    PersistenceSupport.audit(connection, null, "local-admin", "operator.bootstrap-token.rotate",
                            "operator-token", "bootstrap-token", "{}", now);
                }
                connection.commit();
            } catch (Exception failure) {
                PersistenceSupport.rollback(connection, failure);
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not bootstrap local operator", failure);
        }
    }

    Optional<SQLiteControlPlanePersistence.OperatorData> authenticateOperator(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT o.operator_id,o.username,o.role,o.created_at,o.updated_at"
                             + " FROM operator_tokens t JOIN operators o ON o.operator_id=t.operator_id"
                             + " WHERE t.token_hash=? AND t.revoked_at IS NULL")) {
            statement.setString(1, PersistenceSupport.sha256(token));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                return Optional.of(operator(rows));
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not authenticate operator", failure);
        }
    }

    List<SQLiteControlPlanePersistence.OperatorData> listOperators() {
        try (Connection connection = support.open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT operator_id,username,role,created_at,updated_at FROM operators ORDER BY username")) {
            List<SQLiteControlPlanePersistence.OperatorData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(operator(rows));
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list operators", failure);
        }
    }

    void createOperator(SQLiteControlPlanePersistence.OperatorData operator, String tokenHash, String actorId) {
        support.transaction("could not create operator", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO operators(operator_id,username,role,created_at,updated_at)"
                            + " VALUES(?,?,?,?,?)",
                    operator.operatorId(), operator.username(), operator.role().name(),
                    operator.createdAt(), operator.updatedAt());
            PersistenceSupport.update(connection,
                    "INSERT INTO operator_tokens(token_id,operator_id,token_hash,created_at)"
                            + " VALUES(?,?,?,?)",
                    "token-" + UUID.randomUUID(), operator.operatorId(), tokenHash, operator.createdAt());
            PersistenceSupport.audit(connection, null, actorId, "operator.create", "operator",
                    operator.operatorId(), "{\"role\":\"" + operator.role().name() + "\"}", operator.createdAt());
        });
    }

    void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                        String actorId, String now) {
        support.transaction("could not update operator", connection -> {
            PersistenceSupport.update(connection,
                    "UPDATE operators SET role=?,updated_at=? WHERE operator_id=?",
                    role.name(), now, operatorId);
            if (revokeTokens) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE operator_tokens SET revoked_at=? WHERE operator_id=? AND revoked_at IS NULL")) {
                    statement.setString(1, now);
                    statement.setString(2, operatorId);
                    statement.executeUpdate();
                }
            }
            PersistenceSupport.audit(connection, null, actorId,
                    revokeTokens ? "operator.tokens.revoke" : "operator.role.update",
                    "operator", operatorId, "{\"role\":\"" + role.name() + "\"}", now);
        });
    }

    List<SQLiteControlPlanePersistence.ProviderData> listProviders() {
        try (Connection connection = support.open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT p.provider_id,p.name,p.kind,p.base_url,p.model,p.enabled,p.created_at,p.updated_at,"
                             + " EXISTS(SELECT 1 FROM provider_credentials c WHERE c.workspace_id=p.workspace_id"
                             + " AND c.provider_id=p.provider_id) FROM providers p"
                             + " WHERE p.workspace_id='local' ORDER BY p.name")) {
            List<SQLiteControlPlanePersistence.ProviderData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(provider(rows));
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list providers", failure);
        }
    }

    Optional<SQLiteControlPlanePersistence.ProviderData> findProvider(String providerId) {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT p.provider_id,p.name,p.kind,p.base_url,p.model,p.enabled,p.created_at,p.updated_at,"
                             + " EXISTS(SELECT 1 FROM provider_credentials c WHERE c.workspace_id=p.workspace_id"
                             + " AND c.provider_id=p.provider_id) FROM providers p"
                             + " WHERE p.workspace_id=? AND p.provider_id=?")) {
            statement.setString(1, SQLiteControlPlanePersistence.LOCAL_WORKSPACE);
            statement.setString(2, providerId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? Optional.of(provider(rows)) : Optional.empty();
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not find provider", failure);
        }
    }

    void saveProvider(SQLiteControlPlanePersistence.ProviderData provider,
                      SQLiteControlPlanePersistence.StoredSecret secret, String actorId) {
        support.transaction("could not save provider", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO providers(provider_id,workspace_id,name,kind,base_url,model,enabled,"
                            + "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"
                            + " ON CONFLICT(provider_id) DO UPDATE SET name=excluded.name,kind=excluded.kind,"
                            + "base_url=excluded.base_url,model=excluded.model,enabled=excluded.enabled,"
                            + "updated_at=excluded.updated_at",
                    provider.providerId(), SQLiteControlPlanePersistence.LOCAL_WORKSPACE, provider.name(),
                    provider.kind().name(), provider.baseUrl(), provider.model(), provider.enabled() ? 1 : 0,
                    provider.createdAt(), provider.updatedAt());
            if (secret != null) {
                EncryptedSecret encrypted = secret.encrypted();
                PersistenceSupport.update(connection,
                        "INSERT INTO provider_credentials(credential_id,workspace_id,provider_id,"
                                + "format_version,credential_version,nonce,ciphertext,updated_at) VALUES(?,?,?,?,?,?,?,?)"
                                + " ON CONFLICT(workspace_id,provider_id) DO UPDATE SET credential_id=excluded.credential_id,"
                                + "format_version=excluded.format_version,credential_version=excluded.credential_version,"
                                + "nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
                        secret.scope().credentialId(), SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                        provider.providerId(), encrypted.formatVersion(), encrypted.credentialVersion(),
                        encrypted.nonce(), encrypted.ciphertext(), provider.updatedAt());
            }
            PersistenceSupport.audit(connection, null, actorId, "provider.save", "provider", provider.providerId(),
                    "{\"credentialUpdated\":" + (secret != null) + "}", provider.updatedAt());
        });
    }

    Optional<SQLiteControlPlanePersistence.StoredSecret> findProviderSecret(String providerId) {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT credential_id,format_version,credential_version,nonce,ciphertext"
                             + " FROM provider_credentials WHERE workspace_id=? AND provider_id=?")) {
            statement.setString(1, SQLiteControlPlanePersistence.LOCAL_WORKSPACE);
            statement.setString(2, providerId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                SecretScope scope = new SecretScope(
                        SQLiteControlPlanePersistence.LOCAL_WORKSPACE, providerId, rows.getString(1), rows.getLong(3));
                return Optional.of(new SQLiteControlPlanePersistence.StoredSecret(scope,
                        new EncryptedSecret(rows.getInt(2), rows.getLong(3), rows.getBytes(4), rows.getBytes(5))));
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load provider credential", failure);
        }
    }

    void deleteProvider(String providerId, String actorId, String now) {
        support.transaction("could not delete provider", connection -> {
            PersistenceSupport.update(connection,
                    "DELETE FROM providers WHERE workspace_id=? AND provider_id=?",
                    SQLiteControlPlanePersistence.LOCAL_WORKSPACE, providerId);
            PersistenceSupport.audit(connection, null, actorId, "provider.delete", "provider", providerId, "{}", now);
        });
    }

    List<SQLiteControlPlanePersistence.RoleBindingData> listRoleBindings(String projectId) {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT project_id,role,provider_id,model,updated_at,prompt_zh,prompt_en"
                             + " FROM project_ai_role_bindings WHERE project_id=? ORDER BY role")) {
            statement.setString(1, projectId);
            List<SQLiteControlPlanePersistence.RoleBindingData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(binding(rows));
                }
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list role bindings", failure);
        }
    }

    Optional<SQLiteControlPlanePersistence.RoleBindingData> findRoleBinding(String projectId, AgentRole role) {
        return listRoleBindings(projectId).stream().filter(value -> value.role() == role).findFirst();
    }

    void saveRoleBinding(SQLiteControlPlanePersistence.RoleBindingData binding, String actorId) {
        support.transaction("could not save role binding", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO project_ai_role_bindings(project_id,role,workspace_id,provider_id,"
                            + "model,updated_at,prompt_zh,prompt_en) VALUES(?,?,?,?,?,?,?,?) "
                            + "ON CONFLICT(project_id,role) DO UPDATE SET "
                            + "provider_id=excluded.provider_id,model=excluded.model,updated_at=excluded.updated_at,"
                            + "prompt_zh=excluded.prompt_zh,prompt_en=excluded.prompt_en",
                    binding.projectId(), binding.role().name(), SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                    binding.providerId(), binding.model(), binding.updatedAt(), binding.promptZh(), binding.promptEn());
            PersistenceSupport.audit(connection, binding.projectId(), actorId, "role.assign", "ai-role",
                    binding.role().name(), "{\"providerId\":\"" + binding.providerId() + "\"}", binding.updatedAt());
        });
    }

    void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        support.transaction("could not delete role binding", connection -> {
            PersistenceSupport.update(connection,
                    "DELETE FROM project_ai_role_bindings WHERE project_id=? AND role=?",
                    projectId, role.name());
            PersistenceSupport.audit(connection, projectId, actorId, "role.unassign", "ai-role", role.name(), "{}", now);
        });
    }

    void saveAiJob(SQLiteControlPlanePersistence.AiJobData job, String actorId, String action) {
        support.transaction("could not save AI job", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO ai_jobs(ai_job_id,workspace_id,project_id,scan_id,artifact_digest,"
                            + "role,provider_id,model,policy_snapshot_json,authorized,status,stop_reason,stages_json,"
                            + "provider_request_id,elapsed_ms,rounds,tool_summary_json,conclusion_json,created_at,updated_at)"
                            + " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                            + " ON CONFLICT(ai_job_id) DO UPDATE SET status=excluded.status,"
                            + "stop_reason=excluded.stop_reason,stages_json=excluded.stages_json,"
                            + "provider_request_id=excluded.provider_request_id,elapsed_ms=excluded.elapsed_ms,"
                            + "rounds=excluded.rounds,tool_summary_json=excluded.tool_summary_json,"
                            + "conclusion_json=excluded.conclusion_json,updated_at=excluded.updated_at",
                    job.aiJobId(), job.workspaceId(), job.projectId(), job.scanId(), job.artifactDigest(),
                    job.role().name(), job.providerId(), job.model(), job.policySnapshotJson(),
                    job.authorized() ? 1 : 0, job.status(), job.stopReason(), job.stagesJson(),
                    job.providerRequestId(), job.elapsedMillis(), job.rounds(), job.toolSummaryJson(),
                    job.conclusionJson(), job.createdAt(), job.updatedAt());
            PersistenceSupport.audit(connection, job.projectId(), actorId, action, "ai-job", job.aiJobId(),
                    "{\"status\":\"" + job.status() + "\"}", job.updatedAt());
        });
    }

    List<SQLiteControlPlanePersistence.AiJobData> listAiJobs(String projectId) {
        String sql = "SELECT ai_job_id,workspace_id,project_id,scan_id,artifact_digest,role,provider_id,model,"
                + "policy_snapshot_json,authorized,status,stop_reason,stages_json,provider_request_id,"
                + "elapsed_ms,rounds,tool_summary_json,conclusion_json,created_at,updated_at"
                + " FROM ai_jobs" + (projectId == null ? "" : " WHERE project_id=?")
                + " ORDER BY created_at,ai_job_id";
        try (Connection connection = support.open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            if (projectId != null) {
                statement.setString(1, projectId);
            }
            List<SQLiteControlPlanePersistence.AiJobData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(job(rows));
                }
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list AI jobs", failure);
        }
    }

    Optional<SQLiteControlPlanePersistence.AiJobData> findAiJob(String jobId) {
        return listAiJobs(null).stream().filter(value -> value.aiJobId().equals(jobId)).findFirst();
    }

    SQLiteControlPlanePersistence.AiJobEventData appendAiJobEvent(
            SQLiteControlPlanePersistence.AiJobEventData event) {
        Objects.requireNonNull(event, "event");
        event = sanitizedEvent(event);
        validateEvent(event);
        SQLiteControlPlanePersistence.AiJobEventData candidate = event;
        SQLiteControlPlanePersistence.AiJobEventData[] stored = new SQLiteControlPlanePersistence.AiJobEventData[1];
        support.transaction("could not append AI job event", connection -> {
            long sequence;
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT workspace_id,project_id,"
                            + "(SELECT count(*) FROM ai_job_events WHERE ai_job_id=?),"
                            + "(SELECT coalesce(max(sequence_no),0) FROM ai_job_events WHERE ai_job_id=?)"
                            + " FROM ai_jobs WHERE ai_job_id=?")) {
                statement.setString(1, candidate.aiJobId());
                statement.setString(2, candidate.aiJobId());
                statement.setString(3, candidate.aiJobId());
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        throw new SQLException("AI job does not exist");
                    }
                    if (!candidate.workspaceId().equals(rows.getString(1))
                            || !candidate.projectId().equals(rows.getString(2))) {
                        throw new SQLException("AI job event scope mismatch");
                    }
                    if (rows.getInt(3) >= MAX_AI_JOB_EVENTS) {
                        throw new SQLException("AI job event limit reached");
                    }
                    sequence = rows.getLong(4) + 1;
                }
            }
            stored[0] = new SQLiteControlPlanePersistence.AiJobEventData(
                    candidate.aiJobId(), sequence, candidate.workspaceId(),
                    candidate.projectId(), candidate.stage(), candidate.status(),
                    candidate.providerRequestSummary(), candidate.providerResultSummary(),
                    candidate.toolCallName(), candidate.toolArgumentsSummary(),
                    candidate.toolResultStatus(), candidate.modelInferenceSummary(),
                    candidate.failureDiagnostic(), candidate.createdAt());
            PersistenceSupport.update(connection,
                    "INSERT INTO ai_job_events(ai_job_id,sequence_no,workspace_id,project_id,"
                            + "stage,status,provider_request_summary,provider_result_summary,tool_call_name,"
                            + "tool_arguments_summary,tool_result_status,model_inference_summary,"
                            + "failure_diagnostic,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    stored[0].aiJobId(), stored[0].sequence(), stored[0].workspaceId(),
                    stored[0].projectId(), stored[0].stage(), stored[0].status(),
                    stored[0].providerRequestSummary(), stored[0].providerResultSummary(),
                    stored[0].toolCallName(), stored[0].toolArgumentsSummary(),
                    stored[0].toolResultStatus(), stored[0].modelInferenceSummary(),
                    stored[0].failureDiagnostic(), stored[0].createdAt());
        });
        return stored[0];
    }

    List<SQLiteControlPlanePersistence.AiJobEventData> listAiJobEvents(String jobId) {
        Objects.requireNonNull(jobId, "jobId");
        String sql = "SELECT ai_job_id,sequence_no,workspace_id,project_id,stage,status,"
                + "provider_request_summary,provider_result_summary,tool_call_name,"
                + "tool_arguments_summary,tool_result_status,model_inference_summary,"
                + "failure_diagnostic,created_at FROM ai_job_events WHERE ai_job_id=?"
                + " ORDER BY sequence_no";
        try (Connection connection = support.open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, jobId);
            List<SQLiteControlPlanePersistence.AiJobEventData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.AiJobEventData(
                            rows.getString(1), rows.getLong(2), rows.getString(3), rows.getString(4),
                            rows.getString(5), rows.getString(6), rows.getString(7), rows.getString(8),
                            rows.getString(9), rows.getString(10), rows.getString(11), rows.getString(12),
                            rows.getString(13), rows.getString(14)));
                }
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list AI job events", failure);
        }
    }

    void deleteAiJob(SQLiteControlPlanePersistence.AiJobData job, String actorId, String now) {
        support.transaction("could not delete AI job", connection -> {
            PersistenceSupport.update(connection, "DELETE FROM ai_jobs WHERE ai_job_id=?", job.aiJobId());
            PersistenceSupport.audit(connection, job.projectId(), actorId, "ai-job.delete", "ai-job",
                    job.aiJobId(), "{}", now);
        });
    }

    List<SQLiteControlPlanePersistence.AuditData> listAudit(String projectId) {
        String sql = "SELECT audit_event_id,project_id,operator_id,action,target_type,target_id,outcome,"
                + "details_json,created_at FROM audit_events"
                + (projectId == null ? "" : " WHERE project_id=?") + " ORDER BY created_at,audit_event_id";
        try (Connection connection = support.open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            if (projectId != null) {
                statement.setString(1, projectId);
            }
            List<SQLiteControlPlanePersistence.AuditData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.AuditData(
                            rows.getString(1), rows.getString(2), rows.getString(3), rows.getString(4),
                            rows.getString(5), rows.getString(6), rows.getString(7), rows.getString(8),
                            rows.getString(9)));
                }
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not list audit events", failure);
        }
    }

    void recordAudit(String projectId, String operatorId, String action,
                     String targetType, String targetId, String detailsJson, String now) {
        support.transaction("could not write audit event", connection ->
                PersistenceSupport.audit(connection, projectId, operatorId, action, targetType, targetId,
                        detailsJson, now));
    }

    private static SQLiteControlPlanePersistence.OperatorData operator(ResultSet rows) throws SQLException {
        return new SQLiteControlPlanePersistence.OperatorData(rows.getString(1), rows.getString(2),
                OperatorRole.valueOf(rows.getString(3)), rows.getString(4), rows.getString(5));
    }

    private static SQLiteControlPlanePersistence.ProviderData provider(ResultSet rows) throws SQLException {
        return new SQLiteControlPlanePersistence.ProviderData(rows.getString(1), rows.getString(2),
                ProviderKind.valueOf(rows.getString(3)), rows.getString(4), rows.getString(5),
                rows.getInt(6) != 0, rows.getString(7), rows.getString(8), rows.getInt(9) != 0);
    }

    private static SQLiteControlPlanePersistence.RoleBindingData binding(ResultSet rows) throws SQLException {
        return new SQLiteControlPlanePersistence.RoleBindingData(rows.getString(1),
                AgentRole.valueOf(rows.getString(2)), rows.getString(3), rows.getString(4),
                rows.getString(5), rows.getString(6), rows.getString(7));
    }

    private static SQLiteControlPlanePersistence.AiJobData job(ResultSet rows) throws SQLException {
        return new SQLiteControlPlanePersistence.AiJobData(rows.getString(1), rows.getString(2), rows.getString(3),
                rows.getString(4), rows.getString(5), AgentRole.valueOf(rows.getString(6)),
                rows.getString(7), rows.getString(8), rows.getString(9), rows.getInt(10) != 0,
                rows.getString(11), rows.getString(12), rows.getString(13), rows.getString(14),
                rows.getLong(15), rows.getInt(16), rows.getString(17), rows.getString(18),
                rows.getString(19), rows.getString(20));
    }

    private void validateEvent(SQLiteControlPlanePersistence.AiJobEventData event) {
        boundedEventText(event.aiJobId(), 128, false, "aiJobId");
        boundedEventText(event.workspaceId(), 128, false, "workspaceId");
        boundedEventText(event.projectId(), 128, false, "projectId");
        boundedEventText(event.stage(), 64, false, "stage");
        boundedEventText(event.status(), 64, false, "status");
        boundedEventText(event.providerRequestSummary(), 2048, true, "providerRequestSummary");
        boundedEventText(event.providerResultSummary(), 2048, true, "providerResultSummary");
        boundedEventText(event.toolCallName(), 128, true, "toolCallName");
        boundedEventText(event.toolArgumentsSummary(), 1024, true, "toolArgumentsSummary");
        boundedEventText(event.toolResultStatus(), 64, true, "toolResultStatus");
        boundedEventText(event.modelInferenceSummary(), 16_384, true, "modelInferenceSummary");
        boundedEventText(event.failureDiagnostic(), 1024, true, "failureDiagnostic");
        boundedEventText(event.createdAt(), 64, false, "createdAt");
        if (event.sequence() != 0) {
            throw new IllegalArgumentException("event sequence must be assigned by persistence");
        }
        if (!event.stage().matches("[A-Z0-9_]{1,64}")
                || !event.status().matches("[A-Z0-9_]{1,64}")
                || event.toolCallName() != null
                && !event.toolCallName().matches("[A-Za-z0-9_-]{1,128}")
                || event.toolResultStatus() != null
                && !event.toolResultStatus().matches("[A-Z0-9_]{1,64}")) {
            throw new IllegalArgumentException("AI job event code field is invalid");
        }
        validateMetadataJson(event.providerRequestSummary(),
                Set.of("protocol", "round", "maxOutputTokens", "toolDefinitionCount", "outputLanguage"),
                "providerRequestSummary");
        validateMetadataJson(event.providerResultSummary(),
                Set.of("httpStatus", "elapsedMillis", "requestId", "stopReason", "toolCallCount"),
                "providerResultSummary");
        validateMetadataJson(event.toolArgumentsSummary(),
                Set.of("shape", "fieldCount", "encodedBytes", "kind", "limit",
                        "queryPresent", "queryBytes", "evidenceRef", "entrypointRef",
                        "candidateCount", "objectiveBytes",
                        "techniqueId", "authorizationHeaderPresent", "authorizationHeaderBytes",
                        "bladeAuthHeaderPresent", "bladeAuthHeaderBytes"),
                "toolArgumentsSummary");
    }

    private SQLiteControlPlanePersistence.AiJobEventData sanitizedEvent(
            SQLiteControlPlanePersistence.AiJobEventData event) {
        return new SQLiteControlPlanePersistence.AiJobEventData(event.aiJobId(), event.sequence(),
                event.workspaceId(), event.projectId(), event.stage(), event.status(),
                event.providerRequestSummary(), event.providerResultSummary(), event.toolCallName(),
                event.toolArgumentsSummary(), event.toolResultStatus(),
                sanitizedAuditText(event.modelInferenceSummary(), 16_384),
                sanitizedAuditText(event.failureDiagnostic(), 1024), event.createdAt());
    }

    private static String sanitizedAuditText(String value, int maximum) {
        if (value == null) {
            return null;
        }
        String sanitized = value.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("(?i)(api[_ -]?key\\s*[:=]\\s*)\\S+", "$1[REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]");
        return sanitized.length() <= maximum ? sanitized : sanitized.substring(0, maximum);
    }

    private void validateMetadataJson(String value, Set<String> allowedFields, String name) {
        if (value == null) {
            return;
        }
        try {
            var root = support.mapper().readTree(value);
            if (root == null || !root.isObject() || root.isEmpty()) {
                throw new IllegalArgumentException(name + " must be a non-empty metadata object");
            }
            for (var field : root.properties()) {
                if (!allowedFields.contains(field.getKey()) || !field.getValue().isValueNode()
                        || field.getValue().isTextual() && field.getValue().asText().length() > 256) {
                    throw new IllegalArgumentException(name + " contains non-audit metadata");
                }
            }
        } catch (JsonProcessingException invalid) {
            throw new IllegalArgumentException(name + " is not valid JSON metadata", invalid);
        }
    }

    private static void boundedEventText(String value, int maximum, boolean nullable, String name) {
        if (value == null) {
            if (nullable) {
                return;
            }
            throw new IllegalArgumentException(name + " is required");
        }
        if (value.isBlank() || value.length() > maximum
                || value.getBytes(StandardCharsets.UTF_8).length > maximum * 4L
                || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
