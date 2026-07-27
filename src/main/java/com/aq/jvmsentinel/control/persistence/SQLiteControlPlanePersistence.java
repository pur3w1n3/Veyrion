package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.security.ProviderSecretCipher.EncryptedSecret;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretScope;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.StopReason;
import com.aq.jvmsentinel.worker.TaskCheckpoint;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerLease;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Plain-JDBC SQLite persistence for immutable Control Plane snapshots.
 *
 * <p>Only artifact metadata and its controlled host path are stored. Artifact
 * bytes remain in the content source selected by {@code ArtifactRegistry}.</p>
 */
public final class SQLiteControlPlanePersistence {
    private static final int BUSY_TIMEOUT_MILLIS = 5_000;
    private static final int MAX_AI_JOB_EVENTS = 128;
    private static final List<String> MIGRATIONS = List.of(
            "db/migration/V001__control_plane.sql",
            "db/migration/V002__management_configuration.sql",
            "db/migration/V003__provider_protocols.sql",
            "db/migration/V004__bounded_ai_jobs.sql",
            "db/migration/V005__bounded_ai_job_events.sql",
            "db/migration/V006__dynamic_verification_role.sql",
            "db/migration/V007__persistent_worker_state.sql",
            "db/migration/V008__persistent_artifact_uploads.sql",
            "db/migration/V009__persistent_sse_events.sql",
            "db/migration/V010__role_prompt_templates.sql",
            "db/migration/V011__persistent_idempotency_and_pipeline.sql",
            "db/migration/V012__auth_analysis_role.sql",
            "db/migration/V013__persistent_path_runs.sql",
            "db/migration/V014__persistent_experiment_plans.sql",
            "db/migration/V015__add_schema_version.sql",
            "db/migration/V016__branch_hit_map_and_contrast_ledger_snapshots.sql",
            "db/migration/V017__taint_graph_and_ledger_diff.sql",
            "db/migration/V018__fuzz_strategy.sql",
            "db/migration/V019__root_cause.sql",
            "db/migration/V020__verified_findings.sql");
    private static final int SCHEMA_VERSION = MIGRATIONS.size();
    public static final String LOCAL_WORKSPACE = "local";

    private final Path databasePath;
    private final String jdbcUrl;
    private final ObjectMapper mapper = new ObjectMapper();

    public SQLiteControlPlanePersistence(Path databasePath, Path allowedRoot) {
        this.databasePath = controlledDatabasePath(databasePath, allowedRoot);
        this.jdbcUrl = "jdbc:sqlite:" + this.databasePath;
        migrate();
    }

    public Path databasePath() {
        return databasePath;
    }

    public List<IdempotencyData> loadIdempotency() {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT scope,idempotency_key,payload_hash,result_ref,result_json,created_at "
                             + "FROM control_plane_idempotency ORDER BY created_at,scope,idempotency_key")) {
            List<IdempotencyData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new IdempotencyData(rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6)));
                }
            }
            if (result.size() > 50_000) throw new PersistenceException("persistent idempotency limit exceeded");
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not load persistent idempotency records", failure);
        }
    }

    /** Inserts an immutable record or returns the record already committed for the same scope/key. */
    public IdempotencyData putIdempotency(IdempotencyData candidate) {
        Objects.requireNonNull(candidate, "candidate");
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement count = connection.prepareStatement(
                        "SELECT count(*) FROM control_plane_idempotency")) {
                    try (ResultSet rows = count.executeQuery()) {
                        if (rows.next() && rows.getLong(1) >= 50_000) {
                            try (PreparedStatement exists = connection.prepareStatement(
                                    "SELECT 1 FROM control_plane_idempotency WHERE scope=? AND idempotency_key=?")) {
                                exists.setString(1, candidate.scope());
                                exists.setString(2, candidate.key());
                                try (ResultSet found = exists.executeQuery()) {
                                    if (!found.next()) throw new PersistenceException("persistent idempotency limit exceeded");
                                }
                            }
                        }
                    }
                }
                try (PreparedStatement insert = connection.prepareStatement(
                        "INSERT OR IGNORE INTO control_plane_idempotency(scope,idempotency_key,payload_hash,result_ref,result_json,created_at) "
                                + "VALUES(?,?,?,?,?,?)")) {
                    insert.setString(1, candidate.scope());
                    insert.setString(2, candidate.key());
                    insert.setString(3, candidate.payloadHash());
                    insert.setString(4, candidate.resultRef());
                    insert.setString(5, candidate.resultJson());
                    insert.setString(6, candidate.createdAt());
                    insert.executeUpdate();
                }
                IdempotencyData stored;
                try (PreparedStatement select = connection.prepareStatement(
                        "SELECT scope,idempotency_key,payload_hash,result_ref,result_json,created_at "
                                + "FROM control_plane_idempotency WHERE scope=? AND idempotency_key=?")) {
                    select.setString(1, candidate.scope());
                    select.setString(2, candidate.key());
                    try (ResultSet rows = select.executeQuery()) {
                        if (!rows.next()) throw new SQLException("idempotency record was not committed");
                        stored = new IdempotencyData(rows.getString(1), rows.getString(2), rows.getString(3),
                                rows.getString(4), rows.getString(5), rows.getString(6));
                    }
                }
                connection.commit();
                return stored;
            } catch (Exception failure) {
                rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) throw runtime;
                throw new SQLException("idempotency transaction failed", failure);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof PersistenceException persistenceFailure) throw persistenceFailure;
            throw databaseFailure("could not persist idempotency record", failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    public List<PipelineRunData> loadPipelineRuns() {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT scan_id,project_id,actor_id,output_language,armed,next_stage,updated_at "
                             + "FROM audit_pipeline_runs ORDER BY updated_at,scan_id")) {
            List<PipelineRunData> result = new ArrayList<>();
            while (rows.next()) result.add(new PipelineRunData(rows.getString(1), rows.getString(2), rows.getString(3),
                    rows.getString(4), rows.getInt(5) != 0, rows.getString(6), rows.getString(7)));
            if (result.size() > 20_000) throw new PersistenceException("persistent pipeline run limit exceeded");
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not load pipeline runs", failure);
        }
    }

    public void savePipelineRun(PipelineRunData run) {
        Objects.requireNonNull(run, "run");
        transaction("could not persist pipeline run", connection -> update(connection,
                "INSERT INTO audit_pipeline_runs(scan_id,project_id,actor_id,output_language,armed,next_stage,updated_at) "
                        + "VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET project_id=excluded.project_id,"
                        + "actor_id=excluded.actor_id,output_language=excluded.output_language,armed=excluded.armed,"
                        + "next_stage=excluded.next_stage,updated_at=excluded.updated_at",
                run.scanId(), run.projectId(), run.actorId(), run.outputLanguage(), run.armed() ? 1 : 0,
                run.nextStage(), run.updatedAt()));
    }

    public List<ProbePlanData> loadProbePlans() {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT task_id,project_id,artifact_digest,scan_id,target_entry_id,candidate_inputs_json,max_requests,plan_hash,created_at "
                             + "FROM dynamic_probe_plans ORDER BY created_at,task_id")) {
            List<ProbePlanData> result = new ArrayList<>();
            while (rows.next()) result.add(new ProbePlanData(rows.getString(1), rows.getString(2), rows.getString(3),
                    rows.getString(4), rows.getString(5), rows.getString(6), rows.getInt(7), rows.getString(8), rows.getString(9)));
            if (result.size() > 20_000) throw new PersistenceException("persistent probe plan limit exceeded");
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not load probe plans", failure);
        }
    }

    public void saveProbePlan(ProbePlanData plan) {
        Objects.requireNonNull(plan, "plan");
        transaction("could not persist probe plan", connection -> update(connection,
                "INSERT INTO dynamic_probe_plans(task_id,project_id,artifact_digest,scan_id,target_entry_id,candidate_inputs_json,max_requests,plan_hash,created_at) "
                        + "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET candidate_inputs_json=excluded.candidate_inputs_json,"
                        + "max_requests=excluded.max_requests,plan_hash=excluded.plan_hash",
                plan.taskId(), plan.projectId(), plan.artifactDigest(), plan.scanId(), plan.targetEntryId(),
                plan.candidateInputsJson(), plan.maxRequests(), plan.planHash(), plan.createdAt()));
    }

    public List<ExperimentPlanData> loadExperimentPlans() {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT plan_id,scan_id,project_id,artifact_digest,payload_json,created_at,"
                             + "fuzz_strategy_json FROM experiment_plans ORDER BY created_at,plan_id")) {
            List<ExperimentPlanData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new ExperimentPlanData(
                        rows.getString(1), rows.getString(2), rows.getString(3),
                        rows.getString(4), rows.getString(5), rows.getString(6),
                        rows.getString(7)));
            }
            if (result.size() > 20_000) throw new PersistenceException("persistent experiment plan limit exceeded");
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not load experiment plans", failure);
        }
    }

    public List<ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT plan_id,scan_id,project_id,artifact_digest,payload_json,created_at,"
                             + "fuzz_strategy_json FROM experiment_plans WHERE scan_id=? "
                             + "ORDER BY created_at,plan_id")) {
            statement.setString(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<ExperimentPlanData> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(new ExperimentPlanData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6),
                            rows.getString(7)));
                }
                if (result.size() > 256) throw new PersistenceException("per-scan experiment plan limit exceeded");
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not load experiment plans for scan", failure);
        }
    }

    public void saveExperimentPlan(ExperimentPlanData plan) {
        Objects.requireNonNull(plan, "plan");
        String fuzz = plan.fuzzStrategyJson();
        if ((fuzz == null || fuzz.isBlank()) && plan.payloadJson() != null) {
            fuzz = extractFuzzStrategyJson(plan.payloadJson());
        }
        String fuzzColumn = fuzz == null || fuzz.isBlank() ? null : fuzz;
        String finalFuzz = fuzzColumn;
        transaction("could not persist experiment plan", connection -> update(connection,
                "INSERT INTO experiment_plans(plan_id,scan_id,project_id,artifact_digest,payload_json,"
                        + "created_at,fuzz_strategy_json) "
                        + "VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,plan_id) DO UPDATE SET "
                        + "payload_json=excluded.payload_json,created_at=excluded.created_at,"
                        + "fuzz_strategy_json=excluded.fuzz_strategy_json",
                plan.planId(), plan.scanId(), plan.projectId(), plan.artifactDigest(),
                plan.payloadJson(), plan.createdAt(), finalFuzz));
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT path_run_id,payload_json FROM path_runs "
                             + "WHERE project_id=? AND artifact_digest=? AND scan_id=? "
                             + "ORDER BY created_at,path_run_id")) {
            statement.setString(1, projectId);
            statement.setString(2, artifactDigest);
            statement.setString(3, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<ApiDtos.PathRunDto> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(decodePathRun(rows.getString(1), rows.getString(2)));
                    if (result.size() > 50_000) throw new PersistenceException("persistent path run limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not load path runs", failure);
        }
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        Objects.requireNonNull(taskId, "taskId");
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT path_run_id,payload_json FROM path_runs WHERE task_id=? "
                             + "ORDER BY created_at,path_run_id")) {
            statement.setString(1, taskId);
            try (ResultSet rows = statement.executeQuery()) {
                List<ApiDtos.PathRunDto> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(decodePathRun(rows.getString(1), rows.getString(2)));
                    if (result.size() > 20_000) throw new PersistenceException("persistent path run limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not load path runs for task", failure);
        }
    }

    private ApiDtos.PathRunDto decodePathRun(String pathRunId, String payloadJson) {
        try {
            PayloadSchemaGuard.requireJsonSchemaVersion(
                    mapper, payloadJson, "path_run " + pathRunId);
            ApiDtos.PathRunDto run = mapper.readValue(payloadJson, ApiDtos.PathRunDto.class);
            if (!pathRunId.equals(run.pathRunId())) {
                throw new PersistenceException("path run id mismatch for " + pathRunId);
            }
            if (run.schemaVersion() < PayloadSchemaGuard.MIN_SCHEMA_VERSION) {
                throw new PersistenceException(
                        "path_run " + pathRunId + " lacks schemaVersion >= "
                                + PayloadSchemaGuard.MIN_SCHEMA_VERSION
                                + "; run V015 migration");
            }
            return run;
        } catch (PersistenceException failure) {
            throw failure;
        } catch (JsonProcessingException | IllegalArgumentException failure) {
            throw new PersistenceException("persistent path run payload is invalid: " + pathRunId, failure);
        }
    }

    public void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                       String taskId, List<ApiDtos.PathRunDto> pathRuns, String createdAt) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(taskId, "taskId");
        Objects.requireNonNull(createdAt, "createdAt");
        List<ApiDtos.PathRunDto> runs = List.copyOf(pathRuns == null ? List.of() : pathRuns);
        if (runs.size() > 20_000) throw new PersistenceException("path run batch limit exceeded");
        transaction("could not persist path runs", connection -> {
            // DELETE may affect 0 rows on first write; do not use update() which requires exactly one.
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM path_runs WHERE task_id=?")) {
                delete.setString(1, taskId);
                delete.executeUpdate();
            }
            for (ApiDtos.PathRunDto run : runs) {
                if (!scanId.equals(run.scanId())) {
                    throw new PersistenceException("path run scan scope mismatch");
                }
                update(connection,
                        "INSERT INTO path_runs(path_run_id,project_id,artifact_digest,scan_id,task_id,payload_json,created_at) "
                                + "VALUES(?,?,?,?,?,?,?)",
                        run.pathRunId(), projectId, artifactDigest, scanId, taskId, write(run), createdAt);
            }
        });
    }

    public List<ArtifactUploadService.PersistedSession> loadArtifactUploads() {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT upload_id,project_id,file_name,size_bytes,sha256,next_offset,created_at,expires_at " +
                             "FROM artifact_upload_sessions ORDER BY upload_id");
             ResultSet rows = statement.executeQuery()) {
            List<ArtifactUploadService.PersistedSession> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new ArtifactUploadService.PersistedSession(
                        rows.getString(1), rows.getString(2), rows.getString(3), rows.getLong(4),
                        rows.getString(5), rows.getLong(6), Instant.parse(rows.getString(7)),
                        Instant.parse(rows.getString(8))));
            }
            if (result.size() > 256) throw new PersistenceException("persistent upload session limit exceeded");
            return List.copyOf(result);
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof PersistenceException persistenceFailure) throw persistenceFailure;
            throw databaseFailure("could not load persistent artifact uploads",
                    failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    public void persistArtifactUpload(ArtifactUploadService.PersistedSession session) {
        Objects.requireNonNull(session, "session");
        transaction("could not persist artifact upload", connection -> update(connection,
                "INSERT INTO artifact_upload_sessions(upload_id,project_id,file_name,size_bytes,sha256,next_offset,created_at,expires_at) " +
                        "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(upload_id) DO UPDATE SET project_id=excluded.project_id," +
                        "file_name=excluded.file_name,size_bytes=excluded.size_bytes,sha256=excluded.sha256," +
                        "next_offset=excluded.next_offset,created_at=excluded.created_at,expires_at=excluded.expires_at",
                session.uploadId(), session.projectId(), session.fileName(), session.sizeBytes(), session.sha256(),
                session.nextOffset(), session.createdAt().toString(), session.expiresAt().toString()));
    }

    public void deleteArtifactUpload(String uploadId) {
        if (uploadId == null || uploadId.isBlank()) return;
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM artifact_upload_sessions WHERE upload_id=?")) {
            statement.setString(1, uploadId);
            statement.executeUpdate();
        } catch (SQLException failure) {
            throw databaseFailure("could not delete artifact upload", failure);
        }
    }

    public List<VersionedEvent> loadSseEvents() {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT event_id,scan_id,event_type,schema_version,occurred_at,project_id,artifact_digest," +
                             "task_id,idempotency_scope,idempotency_value,payload_json FROM sse_events ORDER BY rowid");
             ResultSet rows = statement.executeQuery()) {
            List<VersionedEvent> result = new ArrayList<>();
            while (rows.next()) {
                EventContext context = rows.getString(6) == null ? null : new EventContext(
                        rows.getString(6), rows.getString(7), rows.getString(2), rows.getString(8));
                result.add(new VersionedEvent(rows.getString(1), rows.getString(3), rows.getInt(4),
                        Instant.parse(rows.getString(5)), context,
                        new IdempotencyKey(rows.getString(9), rows.getString(10)), rows.getString(11)));
            }
            if (result.size() > 100_000) throw new PersistenceException("persistent SSE event limit exceeded");
            return List.copyOf(result);
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof PersistenceException persistenceFailure) throw persistenceFailure;
            throw databaseFailure("could not load persistent SSE events",
                    failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    public void persistSseEvent(String scanId, VersionedEvent event) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(event, "event");
        transaction("could not persist SSE event", connection -> {
            EventContext context = event.context();
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT OR IGNORE INTO sse_events(event_id,scan_id,event_type,schema_version,occurred_at," +
                            "project_id,artifact_digest,task_id,idempotency_scope,idempotency_value,payload_json) " +
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?)")) {
                statement.setString(1, event.eventId());
                statement.setString(2, scanId);
                statement.setString(3, event.eventType());
                statement.setInt(4, event.schemaVersion());
                statement.setString(5, event.occurredAt().toString());
                statement.setString(6, context == null ? null : context.projectId());
                statement.setString(7, context == null ? null : context.artifactDigest());
                statement.setString(8, context == null ? null : context.taskId());
                statement.setString(9, event.idempotencyKey().scope());
                statement.setString(10, event.idempotencyKey().value());
                statement.setString(11, event.payload());
                statement.executeUpdate();
            }
            try (PreparedStatement trim = connection.prepareStatement(
                    "DELETE FROM sse_events WHERE scan_id=? AND event_id NOT IN " +
                            "(SELECT event_id FROM sse_events WHERE scan_id=? ORDER BY rowid DESC LIMIT 256)")) {
                trim.setString(1, scanId);
                trim.setString(2, scanId);
                trim.executeUpdate();
            }
        });
    }

    public WorkerState loadWorkerState() {
        try (Connection connection = open()) {
            List<TaskSnapshot> tasks = new ArrayList<>();
            try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                    "SELECT project_id,artifact_digest,scan_id,task_id,schema_version,target_entry_id,authorized," +
                            "max_wall_clock_seconds,max_cpu_millis,max_memory_bytes,max_disk_bytes,max_trace_bytes," +
                            "network_mode,network_allowlist,required_capability,lifecycle,lease_id,lease_worker_id," +
                            "lease_capability,lease_issued_at,lease_heartbeat_at,lease_expires_at,checkpoint_id," +
                            "checkpoint_trace_sequence,checkpoint_trace_head_digest,checkpoint_created_at,stop_reason," +
                            "failure_code,updated_at FROM worker_tasks ORDER BY rowid")) {
                while (rows.next()) tasks.add(readTask(rows));
            }
            if (tasks.size() > 20_000) throw new PersistenceException("persistent worker task limit exceeded");
            Map<TaskScope, ResourceBudget> budgets = new LinkedHashMap<>();
            for (TaskSnapshot task : tasks) budgets.put(task.scope(), task.spec().resourceBudget());
            List<InMemoryTraceStore.StoredTrace> traces = new ArrayList<>();
            long bytes = 0;
            try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                    "SELECT project_id,artifact_digest,scan_id,task_id,sequence,idempotency_key,schema_version," +
                            "previous_digest,emitted_at,payload,digest FROM worker_trace_chunks " +
                            "ORDER BY project_id,artifact_digest,scan_id,task_id,sequence")) {
                while (rows.next()) {
                    TaskScope scope = new TaskScope(rows.getString(1), rows.getString(2), rows.getString(3), rows.getString(4));
                    if (!budgets.containsKey(scope)) throw new PersistenceException("trace has no task scope");
                    byte[] payload = rows.getBytes(10);
                    bytes = Math.addExact(bytes, payload.length);
                    if (bytes > 1_073_741_824L) throw new PersistenceException("persistent trace byte limit exceeded");
                    TraceChunk chunk = new TraceChunk(rows.getInt(7), scope, rows.getLong(5), rows.getString(8),
                            Instant.parse(rows.getString(9)), payload, rows.getString(11));
                    if (payload.length > budgets.get(scope).maxTraceBytes()) {
                        throw new PersistenceException("trace exceeds task byte budget");
                    }
                    traces.add(new InMemoryTraceStore.StoredTrace(rows.getString(6), chunk));
                }
            }
            if (traces.size() > 100_000) throw new PersistenceException("persistent trace chunk limit exceeded");
            return new WorkerState(tasks, traces);
        } catch (SQLException | ArithmeticException failure) {
            throw databaseFailure("could not load persistent Worker state", failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    public void persistWorkerTask(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        transaction("could not persist Worker task", connection -> {
            WorkerTaskSpec spec = snapshot.spec();
            NetworkPolicy network = spec.networkPolicy();
            WorkerLease lease = snapshot.lease();
            TaskCheckpoint checkpoint = snapshot.checkpoint();
            update(connection, "INSERT INTO worker_tasks(project_id,artifact_digest,scan_id,task_id,schema_version,target_entry_id,authorized," +
                    "max_wall_clock_seconds,max_cpu_millis,max_memory_bytes,max_disk_bytes,max_trace_bytes,network_mode,network_allowlist," +
                    "required_capability,lifecycle,lease_id,lease_worker_id,lease_capability,lease_issued_at,lease_heartbeat_at,lease_expires_at," +
                    "checkpoint_id,checkpoint_trace_sequence,checkpoint_trace_head_digest,checkpoint_created_at,stop_reason,failure_code,updated_at) " +
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) " +
                    "ON CONFLICT(project_id,artifact_digest,scan_id,task_id) DO UPDATE SET schema_version=excluded.schema_version,target_entry_id=excluded.target_entry_id," +
                    "authorized=excluded.authorized,max_wall_clock_seconds=excluded.max_wall_clock_seconds,max_cpu_millis=excluded.max_cpu_millis,max_memory_bytes=excluded.max_memory_bytes," +
                    "max_disk_bytes=excluded.max_disk_bytes,max_trace_bytes=excluded.max_trace_bytes,network_mode=excluded.network_mode,network_allowlist=excluded.network_allowlist," +
                    "required_capability=excluded.required_capability,lifecycle=excluded.lifecycle,lease_id=excluded.lease_id,lease_worker_id=excluded.lease_worker_id," +
                    "lease_capability=excluded.lease_capability,lease_issued_at=excluded.lease_issued_at,lease_heartbeat_at=excluded.lease_heartbeat_at,lease_expires_at=excluded.lease_expires_at," +
                    "checkpoint_id=excluded.checkpoint_id,checkpoint_trace_sequence=excluded.checkpoint_trace_sequence,checkpoint_trace_head_digest=excluded.checkpoint_trace_head_digest," +
                    "checkpoint_created_at=excluded.checkpoint_created_at,stop_reason=excluded.stop_reason,failure_code=excluded.failure_code,updated_at=excluded.updated_at",
                    spec.projectId(), spec.artifactDigest(), spec.scanId(), spec.taskId(), snapshot.schemaVersion(), spec.targetEntryId(), spec.authorized() ? 1 : 0,
                    spec.resourceBudget().maxWallClockSeconds(), spec.resourceBudget().maxCpuMillis(), spec.resourceBudget().maxMemoryBytes(), spec.resourceBudget().maxDiskBytes(), spec.resourceBudget().maxTraceBytes(),
                    network.mode().name(), String.join("\n", network.allowlist()), spec.requiredCapability().name(), snapshot.lifecycle().name(),
                    lease == null ? null : lease.leaseId(), lease == null ? null : lease.workerId(), lease == null ? null : lease.capability().name(),
                    lease == null ? null : lease.issuedAt().toString(), lease == null ? null : lease.heartbeatAt().toString(), lease == null ? null : lease.expiresAt().toString(),
                    checkpoint == null ? null : checkpoint.checkpointId(), checkpoint == null ? null : checkpoint.traceSequence(), checkpoint == null ? null : checkpoint.traceHeadDigest(), checkpoint == null ? null : checkpoint.createdAt().toString(),
                    snapshot.stopReason() == null ? null : snapshot.stopReason().name(), snapshot.failureCode(), snapshot.updatedAt().toString());
        });
    }

    public void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 128
                || idempotencyKey.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("idempotencyKey is invalid");
        }
        Objects.requireNonNull(chunk, "chunk");
        transaction("could not persist Worker trace", connection -> {
            TaskScope scope = chunk.scope();
            try (PreparedStatement existing = connection.prepareStatement("SELECT sequence,schema_version,previous_digest,emitted_at,payload,digest FROM worker_trace_chunks WHERE project_id=? AND artifact_digest=? AND scan_id=? AND task_id=? AND idempotency_key=?")) {
                existing.setString(1, scope.projectId()); existing.setString(2, scope.artifactDigest()); existing.setString(3, scope.scanId()); existing.setString(4, scope.taskId()); existing.setString(5, idempotencyKey);
                try (ResultSet rows = existing.executeQuery()) {
                    if (rows.next()) {
                        TraceChunk prior = new TraceChunk(rows.getInt(2), scope, rows.getLong(1), rows.getString(3), Instant.parse(rows.getString(4)), rows.getBytes(5), rows.getString(6));
                        if (!prior.equals(chunk)) throw new IllegalStateException("idempotency key payload conflict");
                        return;
                    }
                }
            }
            try (PreparedStatement statement = connection.prepareStatement("SELECT sequence,digest FROM worker_trace_chunks WHERE project_id=? AND artifact_digest=? AND scan_id=? AND task_id=? ORDER BY sequence DESC LIMIT 1")) {
                statement.setString(1, scope.projectId()); statement.setString(2, scope.artifactDigest()); statement.setString(3, scope.scanId()); statement.setString(4, scope.taskId());
                try (ResultSet rows = statement.executeQuery()) {
                    boolean found = rows.next();
                    long sequence = found ? rows.getLong(1) + 1 : 0;
                    String previous = found ? rows.getString(2) : null;
                    if (chunk.sequence() != sequence || !Objects.equals(chunk.previousDigest(), previous)) throw new IllegalStateException("trace chain is not contiguous");
                }
            }
            update(connection, "INSERT INTO worker_trace_chunks(project_id,artifact_digest,scan_id,task_id,sequence,idempotency_key,schema_version,previous_digest,emitted_at,payload,digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    scope.projectId(), scope.artifactDigest(), scope.scanId(), scope.taskId(), chunk.sequence(), idempotencyKey, chunk.schemaVersion(), chunk.previousDigest(), chunk.emittedAt().toString(), chunk.payload(), chunk.digest());
        });
    }

    private TaskSnapshot readTask(ResultSet rows) throws SQLException {
        TaskScope scope = new TaskScope(rows.getString(1), rows.getString(2), rows.getString(3), rows.getString(4));
        int schemaVersion = rows.getInt(5);
        PayloadSchemaGuard.requireColumnSchemaVersion(
                schemaVersion, "worker_task " + scope.taskId());
        NetworkPolicy network = new NetworkPolicy(NetworkMode.valueOf(rows.getString(13)), rows.getString(14).isEmpty() ? List.of() : List.of(rows.getString(14).split("\\n", -1)));
        WorkerTaskSpec spec = new WorkerTaskSpec(schemaVersion, scope.projectId(), scope.artifactDigest(), scope.scanId(), scope.taskId(), rows.getString(6), rows.getInt(7) != 0,
                new ResourceBudget(rows.getLong(8), rows.getLong(9), rows.getLong(10), rows.getLong(11), rows.getLong(12)), network, WorkerCapability.valueOf(rows.getString(15)));
        WorkerLease lease = rows.getString(17) == null ? null : new WorkerLease(schemaVersion, scope, rows.getString(17), rows.getString(18), WorkerCapability.valueOf(rows.getString(19)), Instant.parse(rows.getString(20)), Instant.parse(rows.getString(21)), Instant.parse(rows.getString(22)));
        TaskCheckpoint checkpoint = rows.getString(23) == null ? null : new TaskCheckpoint(schemaVersion, scope, rows.getString(23), rows.getLong(24), rows.getString(25), Instant.parse(rows.getString(26)));
        return new TaskSnapshot(schemaVersion, spec, TaskLifecycle.valueOf(rows.getString(16)), lease, checkpoint,
                rows.getString(27) == null ? null : StopReason.valueOf(rows.getString(27)), rows.getString(28), Instant.parse(rows.getString(29)));
    }

    public Snapshot load() {
        try (Connection connection = open()) {
            List<ProjectData> projects = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT project_id,name,status,created_at,updated_at,deleted_at FROM projects ORDER BY created_at,project_id")) {
                while (rows.next()) {
                    projects.add(new ProjectData(rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6)));
                }
            }

            List<ArtifactData> artifacts = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT project_id,artifact_id,artifact_type,normalized_path,size_bytes,"
                                 + "artifact_digest,static_only,registered_at FROM artifacts ORDER BY rowid")) {
                while (rows.next()) {
                    ArtifactDescriptor descriptor = new ArtifactDescriptor(rows.getString(2),
                            ArtifactType.valueOf(rows.getString(3)), Path.of(rows.getString(4)),
                            rows.getLong(5), rows.getString(6), rows.getInt(7) != 0,
                            Instant.parse(rows.getString(8)));
                    artifacts.add(new ArtifactData(rows.getString(1), descriptor));
                }
            }

            Map<String, Map<String, ApiDtos.EvidenceDto>> evidence = loadEvidence(connection);
            Map<String, List<ApiDtos.FindingDto>> findings = loadFindings(connection);
            Map<String, List<ApiDtos.AttackChainDto>> chains = loadChains(connection);
            List<ControlPlaneStore.ScanRecord> scans = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT scan_id,payload_json FROM scans ORDER BY rowid")) {
                while (rows.next()) {
                    String scanId = rows.getString(1);
                    ApiDtos.ScanDto dto = read(rows.getString(2), ApiDtos.ScanDto.class);
                    if (!scanId.equals(dto.scanId())) {
                        throw new PersistenceException("stored scan identifier does not match its payload");
                    }
                    scans.add(new ControlPlaneStore.ScanRecord(dto,
                            evidence.getOrDefault(scanId, Map.of()),
                            findings.getOrDefault(scanId, List.of()),
                            chains.getOrDefault(scanId, List.of())));
                }
            }
            return new Snapshot(projects, artifacts, scans);
        } catch (SQLException failure) {
            throw databaseFailure("could not load Control Plane state", failure);
        }
    }

    public void insertProject(String id, String name, String status, String createdAt, String updatedAt,
                              String actorId) {
        transaction("could not create project", connection -> {
            update(connection, "INSERT INTO projects(project_id,name,status,created_at,updated_at) VALUES(?,?,?,?,?)",
                    id, name, status, createdAt, updatedAt);
            audit(connection, id, actorId, "project.create", "project", id, "{}", createdAt);
        });
    }

    public void updateProject(String id, String name, String status, String updatedAt, String actorId) {
        transaction("could not update project", connection -> {
            update(connection, "UPDATE projects SET name=?,status=?,updated_at=? WHERE project_id=? AND deleted_at IS NULL",
                    name, status, updatedAt, id);
            audit(connection, id, actorId, "project.update", "project", id,
                    "{\"status\":\"" + status + "\"}", updatedAt);
        });
    }

    public void softDeleteProject(String id, String deletedAt, String actorId) {
        transaction("could not delete project", connection -> {
            audit(connection, id, actorId, "project.delete", "project", id, "{}", deletedAt);
            update(connection, "UPDATE projects SET status='DELETED',updated_at=?,deleted_at=? "
                            + "WHERE project_id=? AND deleted_at IS NULL",
                    deletedAt, deletedAt, id);
        });
    }

    public void insertArtifact(String projectId, ArtifactDescriptor descriptor, String actorId) {
        transaction("could not register artifact", connection -> {
            update(connection, "INSERT INTO artifacts(project_id,artifact_digest,artifact_id,artifact_type,"
                            + "normalized_path,size_bytes,static_only,registered_at) VALUES(?,?,?,?,?,?,?,?) "
                            + "ON CONFLICT(project_id,artifact_digest) DO UPDATE SET artifact_id=excluded.artifact_id,"
                            + "artifact_type=excluded.artifact_type,normalized_path=excluded.normalized_path,"
                            + "size_bytes=excluded.size_bytes,static_only=excluded.static_only,"
                            + "registered_at=excluded.registered_at",
                    projectId, descriptor.sha256(), descriptor.artifactId(), descriptor.type().name(),
                    descriptor.normalizedPath().toString(), descriptor.sizeBytes(), descriptor.staticOnly() ? 1 : 0,
                    descriptor.registeredAt().toString());
            audit(connection, projectId, actorId, "artifact.register", "artifact",
                    descriptor.artifactId(), "{\"digest\":\"" + descriptor.sha256() + "\"}",
                    descriptor.registeredAt().toString());
        });
    }

    public void insertScan(ControlPlaneStore.ScanRecord record, String actorId) {
        Objects.requireNonNull(record, "record");
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                ApiDtos.ScanDto dto = record.dto();
                update(connection, "INSERT INTO scans(scan_id,project_id,artifact_digest,payload_json,created_at)"
                                + " VALUES(?,?,?,?,?)",
                        dto.scanId(), dto.projectId(), dto.artifactDigest(), write(dto), dto.createdAt());
                for (ApiDtos.EvidenceDto item : record.evidence().values()) {
                    update(connection, "INSERT INTO evidence(evidence_id,scan_id,project_id,payload_json) VALUES(?,?,?,?)",
                            item.evidenceId(), dto.scanId(), dto.projectId(), write(item));
                }
                for (ApiDtos.FindingDto item : record.findings()) {
                    update(connection,
                            "INSERT INTO findings(finding_id,scan_id,project_id,payload_json,root_cause_json)"
                                    + " VALUES(?,?,?,?,?)",
                            item.findingId(), dto.scanId(), dto.projectId(), write(item),
                            rootCauseColumnJson(item));
                }
                for (ApiDtos.AttackChainDto item : record.chains()) {
                    update(connection, "INSERT INTO attack_chains(chain_id,scan_id,project_id,payload_json) VALUES(?,?,?,?)",
                            item.chainId(), dto.scanId(), dto.projectId(), write(item));
                }
                audit(connection, dto.projectId(), actorId, "scan.run", "scan", dto.scanId(),
                        "{\"verificationStatus\":\"" + dto.verificationStatus() + "\"}", dto.createdAt());
                connection.commit();
            } catch (Exception failure) {
                rollback(connection, failure);
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not persist scan", failure);
        }
    }

    public void bootstrapOperator(String token, String now) {
        Objects.requireNonNull(token, "token");
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                int count;
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery("SELECT count(*) FROM operators")) {
                    count = rows.next() ? rows.getInt(1) : 0;
                }
                if (count == 0) {
                    update(connection, "INSERT INTO operators(operator_id,username,role,created_at,updated_at)"
                                    + " VALUES(?,?,?,?,?)",
                            "local-admin", "local-admin", OperatorRole.ADMINISTRATOR.name(), now, now);
                    update(connection, "INSERT INTO operator_tokens(token_id,operator_id,token_hash,created_at)"
                                    + " VALUES(?,?,?,?)",
                            "bootstrap-token", "local-admin", sha256(token), now);
                    audit(connection, null, "local-admin", "operator.bootstrap",
                            "operator", "local-admin", "{}", now);
                } else {
                    try (PreparedStatement administrator = connection.prepareStatement(
                            "SELECT role FROM operators WHERE operator_id='local-admin'")) {
                        try (ResultSet rows = administrator.executeQuery()) {
                            if (!rows.next() || !OperatorRole.ADMINISTRATOR.name().equals(rows.getString(1))) {
                                throw new PersistenceException(
                                        "persistent local administrator is missing or no longer an administrator");
                            }
                        }
                    }
                    update(connection, "UPDATE operator_tokens SET token_hash=?,created_at=?,revoked_at=NULL"
                                    + " WHERE token_id='bootstrap-token' AND operator_id='local-admin'",
                            sha256(token), now);
                    audit(connection, null, "local-admin", "operator.bootstrap-token.rotate",
                            "operator-token", "bootstrap-token", "{}", now);
                }
                connection.commit();
            } catch (Exception failure) {
                rollback(connection, failure);
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not bootstrap local operator", failure);
        }
    }

    public Optional<OperatorData> authenticateOperator(String token) {
        if (token == null || token.isBlank()) return Optional.empty();
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT o.operator_id,o.username,o.role,o.created_at,o.updated_at"
                             + " FROM operator_tokens t JOIN operators o ON o.operator_id=t.operator_id"
                             + " WHERE t.token_hash=? AND t.revoked_at IS NULL")) {
            statement.setString(1, sha256(token));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return Optional.empty();
                return Optional.of(operator(rows));
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not authenticate operator", failure);
        }
    }

    public List<OperatorData> listOperators() {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT operator_id,username,role,created_at,updated_at FROM operators ORDER BY username")) {
            List<OperatorData> result = new ArrayList<>();
            while (rows.next()) result.add(operator(rows));
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list operators", failure);
        }
    }

    public void createOperator(OperatorData operator, String tokenHash, String actorId) {
        transaction("could not create operator", connection -> {
            update(connection, "INSERT INTO operators(operator_id,username,role,created_at,updated_at)"
                            + " VALUES(?,?,?,?,?)",
                    operator.operatorId(), operator.username(), operator.role().name(),
                    operator.createdAt(), operator.updatedAt());
            update(connection, "INSERT INTO operator_tokens(token_id,operator_id,token_hash,created_at)"
                            + " VALUES(?,?,?,?)",
                    "token-" + UUID.randomUUID(), operator.operatorId(), tokenHash, operator.createdAt());
            audit(connection, null, actorId, "operator.create", "operator",
                    operator.operatorId(), "{\"role\":\"" + operator.role().name() + "\"}", operator.createdAt());
        });
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                               String actorId, String now) {
        transaction("could not update operator", connection -> {
            update(connection, "UPDATE operators SET role=?,updated_at=? WHERE operator_id=?",
                    role.name(), now, operatorId);
            if (revokeTokens) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE operator_tokens SET revoked_at=? WHERE operator_id=? AND revoked_at IS NULL")) {
                    statement.setString(1, now);
                    statement.setString(2, operatorId);
                    statement.executeUpdate();
                }
            }
            audit(connection, null, actorId, revokeTokens ? "operator.tokens.revoke" : "operator.role.update",
                    "operator", operatorId, "{\"role\":\"" + role.name() + "\"}", now);
        });
    }

    public List<ProviderData> listProviders() {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT p.provider_id,p.name,p.kind,p.base_url,p.model,p.enabled,p.created_at,p.updated_at,"
                             + " EXISTS(SELECT 1 FROM provider_credentials c WHERE c.workspace_id=p.workspace_id"
                             + " AND c.provider_id=p.provider_id) FROM providers p"
                             + " WHERE p.workspace_id='local' ORDER BY p.name")) {
            List<ProviderData> result = new ArrayList<>();
            while (rows.next()) result.add(provider(rows));
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list providers", failure);
        }
    }

    public Optional<ProviderData> findProvider(String providerId) {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT p.provider_id,p.name,p.kind,p.base_url,p.model,p.enabled,p.created_at,p.updated_at,"
                             + " EXISTS(SELECT 1 FROM provider_credentials c WHERE c.workspace_id=p.workspace_id"
                             + " AND c.provider_id=p.provider_id) FROM providers p"
                             + " WHERE p.workspace_id=? AND p.provider_id=?")) {
            statement.setString(1, LOCAL_WORKSPACE);
            statement.setString(2, providerId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? Optional.of(provider(rows)) : Optional.empty();
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not find provider", failure);
        }
    }

    public void saveProvider(ProviderData provider, StoredSecret secret, String actorId) {
        transaction("could not save provider", connection -> {
            update(connection, "INSERT INTO providers(provider_id,workspace_id,name,kind,base_url,model,enabled,"
                            + "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"
                            + " ON CONFLICT(provider_id) DO UPDATE SET name=excluded.name,kind=excluded.kind,"
                            + "base_url=excluded.base_url,model=excluded.model,enabled=excluded.enabled,"
                            + "updated_at=excluded.updated_at",
                    provider.providerId(), LOCAL_WORKSPACE, provider.name(), provider.kind().name(),
                    provider.baseUrl(), provider.model(), provider.enabled() ? 1 : 0,
                    provider.createdAt(), provider.updatedAt());
            if (secret != null) {
                EncryptedSecret encrypted = secret.encrypted();
                update(connection, "INSERT INTO provider_credentials(credential_id,workspace_id,provider_id,"
                                + "format_version,credential_version,nonce,ciphertext,updated_at) VALUES(?,?,?,?,?,?,?,?)"
                                + " ON CONFLICT(workspace_id,provider_id) DO UPDATE SET credential_id=excluded.credential_id,"
                                + "format_version=excluded.format_version,credential_version=excluded.credential_version,"
                                + "nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
                        secret.scope().credentialId(), LOCAL_WORKSPACE, provider.providerId(),
                        encrypted.formatVersion(), encrypted.credentialVersion(), encrypted.nonce(),
                        encrypted.ciphertext(), provider.updatedAt());
            }
            audit(connection, null, actorId, "provider.save", "provider", provider.providerId(),
                    "{\"credentialUpdated\":" + (secret != null) + "}", provider.updatedAt());
        });
    }

    public Optional<StoredSecret> findProviderSecret(String providerId) {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT credential_id,format_version,credential_version,nonce,ciphertext"
                             + " FROM provider_credentials WHERE workspace_id=? AND provider_id=?")) {
            statement.setString(1, LOCAL_WORKSPACE);
            statement.setString(2, providerId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return Optional.empty();
                SecretScope scope = new SecretScope(LOCAL_WORKSPACE, providerId, rows.getString(1), rows.getLong(3));
                return Optional.of(new StoredSecret(scope, new EncryptedSecret(rows.getInt(2), rows.getLong(3),
                        rows.getBytes(4), rows.getBytes(5))));
            }
        } catch (SQLException failure) {
            throw databaseFailure("could not load provider credential", failure);
        }
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        transaction("could not delete provider", connection -> {
            update(connection, "DELETE FROM providers WHERE workspace_id=? AND provider_id=?",
                    LOCAL_WORKSPACE, providerId);
            audit(connection, null, actorId, "provider.delete", "provider", providerId, "{}", now);
        });
    }

    public List<RoleBindingData> listRoleBindings(String projectId) {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT project_id,role,provider_id,model,updated_at,prompt_zh,prompt_en"
                             + " FROM project_ai_role_bindings WHERE project_id=? ORDER BY role")) {
            statement.setString(1, projectId);
            List<RoleBindingData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) result.add(binding(rows));
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list role bindings", failure);
        }
    }

    public Optional<RoleBindingData> findRoleBinding(String projectId, AgentRole role) {
        return listRoleBindings(projectId).stream().filter(value -> value.role() == role).findFirst();
    }

    public void saveRoleBinding(RoleBindingData binding, String actorId) {
        transaction("could not save role binding", connection -> {
            update(connection, "INSERT INTO project_ai_role_bindings(project_id,role,workspace_id,provider_id,"
                            + "model,updated_at,prompt_zh,prompt_en) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project_id,role) DO UPDATE SET "
                            + "provider_id=excluded.provider_id,model=excluded.model,updated_at=excluded.updated_at,"
                            + "prompt_zh=excluded.prompt_zh,prompt_en=excluded.prompt_en",
                    binding.projectId(), binding.role().name(), LOCAL_WORKSPACE, binding.providerId(),
                    binding.model(), binding.updatedAt(), binding.promptZh(), binding.promptEn());
            audit(connection, binding.projectId(), actorId, "role.assign", "ai-role",
                    binding.role().name(), "{\"providerId\":\"" + binding.providerId() + "\"}", binding.updatedAt());
        });
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        transaction("could not delete role binding", connection -> {
            update(connection, "DELETE FROM project_ai_role_bindings WHERE project_id=? AND role=?",
                    projectId, role.name());
            audit(connection, projectId, actorId, "role.unassign", "ai-role", role.name(), "{}", now);
        });
    }

    public void saveAiJob(AiJobData job, String actorId, String action) {
        transaction("could not save AI job", connection -> {
            update(connection, "INSERT INTO ai_jobs(ai_job_id,workspace_id,project_id,scan_id,artifact_digest,"
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
            audit(connection, job.projectId(), actorId, action, "ai-job", job.aiJobId(),
                    "{\"status\":\"" + job.status() + "\"}", job.updatedAt());
        });
    }

    public List<AiJobData> listAiJobs(String projectId) {
        String sql = "SELECT ai_job_id,workspace_id,project_id,scan_id,artifact_digest,role,provider_id,model,"
                + "policy_snapshot_json,authorized,status,stop_reason,stages_json,provider_request_id,"
                + "elapsed_ms,rounds,tool_summary_json,conclusion_json,created_at,updated_at"
                + " FROM ai_jobs" + (projectId == null ? "" : " WHERE project_id=?")
                + " ORDER BY created_at,ai_job_id";
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            if (projectId != null) statement.setString(1, projectId);
            List<AiJobData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) result.add(job(rows));
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list AI jobs", failure);
        }
    }

    public Optional<AiJobData> findAiJob(String jobId) {
        return listAiJobs(null).stream().filter(value -> value.aiJobId().equals(jobId)).findFirst();
    }

    public AiJobEventData appendAiJobEvent(AiJobEventData event) {
        Objects.requireNonNull(event, "event");
        event = sanitizedEvent(event);
        validateEvent(event);
        AiJobEventData candidate = event;
        AiJobEventData[] stored = new AiJobEventData[1];
        transaction("could not append AI job event", connection -> {
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
                    if (!rows.next()) throw new SQLException("AI job does not exist");
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
            stored[0] = new AiJobEventData(candidate.aiJobId(), sequence, candidate.workspaceId(),
                    candidate.projectId(), candidate.stage(), candidate.status(),
                    candidate.providerRequestSummary(), candidate.providerResultSummary(),
                    candidate.toolCallName(), candidate.toolArgumentsSummary(),
                    candidate.toolResultStatus(), candidate.modelInferenceSummary(),
                    candidate.failureDiagnostic(), candidate.createdAt());
            update(connection, "INSERT INTO ai_job_events(ai_job_id,sequence_no,workspace_id,project_id,"
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

    public List<AiJobEventData> listAiJobEvents(String jobId) {
        Objects.requireNonNull(jobId, "jobId");
        String sql = "SELECT ai_job_id,sequence_no,workspace_id,project_id,stage,status,"
                + "provider_request_summary,provider_result_summary,tool_call_name,"
                + "tool_arguments_summary,tool_result_status,model_inference_summary,"
                + "failure_diagnostic,created_at FROM ai_job_events WHERE ai_job_id=?"
                + " ORDER BY sequence_no";
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, jobId);
            List<AiJobEventData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new AiJobEventData(rows.getString(1), rows.getLong(2),
                            rows.getString(3), rows.getString(4), rows.getString(5),
                            rows.getString(6), rows.getString(7), rows.getString(8),
                            rows.getString(9), rows.getString(10), rows.getString(11),
                            rows.getString(12), rows.getString(13), rows.getString(14)));
                }
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list AI job events", failure);
        }
    }

    public void deleteAiJob(AiJobData job, String actorId, String now) {
        transaction("could not delete AI job", connection -> {
            update(connection, "DELETE FROM ai_jobs WHERE ai_job_id=?", job.aiJobId());
            audit(connection, job.projectId(), actorId, "ai-job.delete", "ai-job", job.aiJobId(), "{}", now);
        });
    }

    public List<AuditData> listAudit(String projectId) {
        String sql = "SELECT audit_event_id,project_id,operator_id,action,target_type,target_id,outcome,"
                + "details_json,created_at FROM audit_events"
                + (projectId == null ? "" : " WHERE project_id=?") + " ORDER BY created_at,audit_event_id";
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            if (projectId != null) statement.setString(1, projectId);
            List<AuditData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) result.add(new AuditData(rows.getString(1), rows.getString(2),
                        rows.getString(3), rows.getString(4), rows.getString(5), rows.getString(6),
                        rows.getString(7), rows.getString(8), rows.getString(9)));
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw databaseFailure("could not list audit events", failure);
        }
    }

    public void recordAudit(String projectId, String operatorId, String action,
                            String targetType, String targetId, String detailsJson, String now) {
        transaction("could not write audit event", connection ->
                audit(connection, projectId, operatorId, action, targetType, targetId, detailsJson, now));
    }

    private Map<String, Map<String, ApiDtos.EvidenceDto>> loadEvidence(Connection connection) throws SQLException {
        Map<String, Map<String, ApiDtos.EvidenceDto>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT evidence_id,scan_id,payload_json FROM evidence ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.EvidenceDto dto = read(rows.getString(3), ApiDtos.EvidenceDto.class);
                if (!rows.getString(1).equals(dto.evidenceId())) {
                    throw new PersistenceException("stored evidence identifier does not match its payload");
                }
                result.computeIfAbsent(rows.getString(2), ignored -> new LinkedHashMap<>())
                        .put(dto.evidenceId(), dto);
            }
        }
        return result;
    }

    private Map<String, List<ApiDtos.FindingDto>> loadFindings(Connection connection) throws SQLException {
        Map<String, List<ApiDtos.FindingDto>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT finding_id,scan_id,payload_json,root_cause_json FROM findings ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.FindingDto dto = read(rows.getString(3), ApiDtos.FindingDto.class);
                if (!rows.getString(1).equals(dto.findingId())) {
                    throw new PersistenceException("stored finding identifier does not match its payload");
                }
                dto = mergeRootCauseColumn(dto, rows.getString(4));
                result.computeIfAbsent(rows.getString(2), ignored -> new ArrayList<>()).add(dto);
            }
        }
        return result;
    }

    private Map<String, List<ApiDtos.AttackChainDto>> loadChains(Connection connection) throws SQLException {
        Map<String, List<ApiDtos.AttackChainDto>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT chain_id,scan_id,payload_json FROM attack_chains ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.AttackChainDto dto = read(rows.getString(3), ApiDtos.AttackChainDto.class);
                if (!rows.getString(1).equals(dto.chainId())) {
                    throw new PersistenceException("stored attack-chain identifier does not match its payload");
                }
                result.computeIfAbsent(rows.getString(2), ignored -> new ArrayList<>()).add(dto);
            }
        }
        return result;
    }

    private void migrate() {
        List<String> sql = MIGRATIONS.stream().map(SQLiteControlPlanePersistence::resource).toList();
        List<String> checksums = sql.stream().map(SQLiteControlPlanePersistence::sha256).toList();
        try (Connection connection = open()) {
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS schema_migrations("
                        + "version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL)");
            }
            int current = 0;
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT version,name,checksum FROM schema_migrations ORDER BY version")) {
                while (rows.next()) {
                    int version = rows.getInt(1);
                    if (version != current + 1 || version > SCHEMA_VERSION) {
                        throw new MigrationException("unsupported or non-contiguous database schema version");
                    }
                    String expectedName = MIGRATIONS.get(version - 1);
                    String appliedName = rows.getString(2);
                    String expectedChecksum = checksums.get(version - 1);
                    String appliedChecksum = rows.getString(3);
                    if (!expectedName.equals(appliedName) || !expectedChecksum.equals(appliedChecksum)) {
                        throw new MigrationException(
                                "database migration checksum mismatch for version " + version
                                        + " (" + expectedName + "); applied migrations must not be rewritten. "
                                        + "For local development, back up and recreate "
                                        + "<Artifacts>/.veyrion/control-plane.db after confirming no needed state");
                    }
                    current = version;
                }
            }
            if (current == SCHEMA_VERSION) return;
            for (int migration = current; migration < SCHEMA_VERSION; migration++) {
                // SQLite ignores PRAGMA foreign_keys inside an open transaction; disable first.
                try (Statement statement = connection.createStatement()) {
                    statement.execute("PRAGMA foreign_keys=OFF");
                    requirePragma(statement, "foreign_keys", "0");
                }
                connection.setAutoCommit(false);
                try {
                    for (String statementSql : splitMigrationStatements(sql.get(migration))) {
                        if (isForeignKeysPragma(statementSql)) {
                            continue;
                        }
                        try (Statement statement = connection.createStatement()) {
                            statement.execute(statementSql);
                        } catch (SQLException alreadyApplied) {
                            // Idempotent ADD COLUMN / CREATE INDEX for upgrade fixtures
                            // that keep tables while replaying later migrations.
                            if (!isIdempotentSchemaReplayError(statementSql, alreadyApplied)) {
                                throw alreadyApplied;
                            }
                        }
                    }
                    update(connection, "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                            migration + 1, MIGRATIONS.get(migration), checksums.get(migration), Instant.now().toString());
                    connection.commit();
                } catch (Exception failure) {
                    rollback(connection, failure);
                    throw new MigrationException("database migration failed", failure);
                } finally {
                    connection.setAutoCommit(true);
                    try (Statement statement = connection.createStatement()) {
                        statement.execute("PRAGMA foreign_keys=ON");
                        requirePragma(statement, "foreign_keys", "1");
                    }
                }
            }
        } catch (SQLException failure) {
            throw new MigrationException("database migration failed", failure);
        }
    }

    private Connection open() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        boolean configured = false;
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys=ON");
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=FULL");
            statement.execute("PRAGMA busy_timeout=" + BUSY_TIMEOUT_MILLIS);
            statement.execute("PRAGMA trusted_schema=OFF");
            requirePragma(statement, "foreign_keys", "1");
            requirePragma(statement, "journal_mode", "wal");
            requirePragma(statement, "synchronous", "2");
            requirePragma(statement, "busy_timeout", Integer.toString(BUSY_TIMEOUT_MILLIS));
            requirePragma(statement, "trusted_schema", "0");
            configured = true;
            return connection;
        } finally {
            if (!configured) connection.close();
        }
    }

    private static void requirePragma(Statement statement, String name, String expected) throws SQLException {
        try (ResultSet result = statement.executeQuery("PRAGMA " + name)) {
            if (!result.next() || !expected.equals(result.getString(1))) {
                throw new SQLException("required SQLite PRAGMA was not applied: " + name);
            }
        }
    }

    /** Split migration SQL on semicolons after stripping line comments (so `-- ...; ...` cannot break DDL). */
    static List<String> splitMigrationStatements(String migrationSql) {
        StringBuilder withoutComments = new StringBuilder(migrationSql.length());
        for (String line : migrationSql.split("\n", -1)) {
            int commentAt = line.indexOf("--");
            withoutComments.append(commentAt >= 0 ? line.substring(0, commentAt) : line).append('\n');
        }
        List<String> statements = new ArrayList<>();
        for (String statementSql : withoutComments.toString().split(";")) {
            String trimmed = statementSql.trim();
            if (!trimmed.isEmpty()) {
                statements.add(trimmed);
            }
        }
        return statements;
    }

    private static boolean isForeignKeysPragma(String statementSql) {
        String normalized = statementSql.replaceAll("\\s+", " ").trim();
        return normalized.regionMatches(true, 0, "PRAGMA foreign_keys", 0, "PRAGMA foreign_keys".length());
    }

    private static boolean isIdempotentSchemaReplayError(String statementSql, SQLException failure) {
        if (statementSql == null || failure == null) return false;
        String normalized = statementSql.replaceAll("\\s+", " ").trim().toUpperCase(Locale.ROOT);
        String message = failure.getMessage();
        if (message == null) return false;
        String lower = message.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("ALTER TABLE") && normalized.contains("ADD COLUMN")
                && lower.contains("duplicate column name")) {
            return true;
        }
        return normalized.startsWith("CREATE INDEX") && lower.contains("already exists");
    }

    private void executeUpdate(String sql, Object... values) {
        try (Connection connection = open()) {
            update(connection, sql, values);
        } catch (SQLException failure) {
            throw databaseFailure("could not persist Control Plane state", failure);
        }
    }

    private static void update(Connection connection, String sql, Object... values) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < values.length; i++) statement.setObject(i + 1, values[i]);
            int changed = statement.executeUpdate();
            if (changed != 1) throw new SQLException("persistence update affected " + changed + " rows");
        }
    }

    private void transaction(String message, SqlWork work) {
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                work.run(connection);
                connection.commit();
            } catch (Exception failure) {
                rollback(connection, failure);
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw databaseFailure(message, failure);
        }
    }

    private static void audit(Connection connection, String projectId, String operatorId, String action,
                              String targetType, String targetId, String details, String now) throws SQLException {
        update(connection, "INSERT INTO audit_events(audit_event_id,project_id,operator_id,action,target_type,"
                        + "target_id,outcome,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                "audit-" + UUID.randomUUID(), projectId, operatorId, action, targetType, targetId,
                "SUCCESS", details, now);
    }

    private static OperatorData operator(ResultSet rows) throws SQLException {
        return new OperatorData(rows.getString(1), rows.getString(2),
                OperatorRole.valueOf(rows.getString(3)), rows.getString(4), rows.getString(5));
    }

    private static ProviderData provider(ResultSet rows) throws SQLException {
        return new ProviderData(rows.getString(1), rows.getString(2),
                ProviderKind.valueOf(rows.getString(3)), rows.getString(4), rows.getString(5),
                rows.getInt(6) != 0, rows.getString(7), rows.getString(8), rows.getInt(9) != 0);
    }

    private static RoleBindingData binding(ResultSet rows) throws SQLException {
        return new RoleBindingData(rows.getString(1), AgentRole.valueOf(rows.getString(2)),
                rows.getString(3), rows.getString(4), rows.getString(5), rows.getString(6), rows.getString(7));
    }

    private static AiJobData job(ResultSet rows) throws SQLException {
        return new AiJobData(rows.getString(1), rows.getString(2), rows.getString(3),
                rows.getString(4), rows.getString(5), AgentRole.valueOf(rows.getString(6)),
                rows.getString(7), rows.getString(8), rows.getString(9), rows.getInt(10) != 0,
                rows.getString(11), rows.getString(12), rows.getString(13), rows.getString(14),
                rows.getLong(15), rows.getInt(16), rows.getString(17), rows.getString(18),
                rows.getString(19), rows.getString(20));
    }

    private void validateEvent(AiJobEventData event) {
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
        if (event.sequence() != 0) throw new IllegalArgumentException("event sequence must be assigned by persistence");
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
                        // Bounded sandbox_probe / plan_propose redaction fields (no raw secrets).
                        "techniqueId", "authorizationHeaderPresent", "authorizationHeaderBytes",
                        "bladeAuthHeaderPresent", "bladeAuthHeaderBytes"),
                "toolArgumentsSummary");
    }

    private AiJobEventData sanitizedEvent(AiJobEventData event) {
        return new AiJobEventData(event.aiJobId(), event.sequence(), event.workspaceId(),
                event.projectId(), event.stage(), event.status(), event.providerRequestSummary(),
                event.providerResultSummary(), event.toolCallName(), event.toolArgumentsSummary(),
                event.toolResultStatus(), sanitizedAuditText(event.modelInferenceSummary(), 16_384),
                sanitizedAuditText(event.failureDiagnostic(), 1024), event.createdAt());
    }

    private static String sanitizedAuditText(String value, int maximum) {
        if (value == null) return null;
        String sanitized = value.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("(?i)(api[_ -]?key\\s*[:=]\\s*)\\S+", "$1[REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]");
        return sanitized.length() <= maximum ? sanitized : sanitized.substring(0, maximum);
    }

    private void validateMetadataJson(String value, Set<String> allowedFields, String name) {
        if (value == null) return;
        try {
            var root = mapper.readTree(value);
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
            if (nullable) return;
            throw new IllegalArgumentException(name + " is required");
        }
        if (value.isBlank() || value.length() > maximum
                || value.getBytes(StandardCharsets.UTF_8).length > maximum * 4L
                || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new PersistenceException("could not encode persistent snapshot", failure);
        }
    }

    private <T> T read(String value, Class<T> type) {
        try {
            return mapper.readValue(value, type);
        } catch (JsonProcessingException failure) {
            throw new PersistenceException("persistent snapshot is invalid", failure);
        }
    }

    private String rootCauseColumnJson(ApiDtos.FindingDto item) {
        if (item == null || item.rootCause() == null || item.rootCause().isEmpty()) return null;
        return write(item.rootCause());
    }

    private ApiDtos.FindingDto mergeRootCauseColumn(ApiDtos.FindingDto dto, String rootCauseJson) {
        if (dto == null) return null;
        if (dto.rootCause() != null && !dto.rootCause().isEmpty()) return dto;
        if (rootCauseJson == null || rootCauseJson.isBlank()) return dto;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = mapper.readValue(rootCauseJson, Map.class);
            if (parsed == null || parsed.isEmpty()) return dto;
            return dto.withRootCause(parsed);
        } catch (JsonProcessingException failure) {
            throw new PersistenceException("stored finding root_cause_json is invalid", failure);
        }
    }

    private String extractFuzzStrategyJson(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) return null;
        try {
            var root = mapper.readTree(payloadJson);
            var node = root.get("fuzzStrategyJson");
            if (node == null || node.isNull()) node = root.get("fuzzStrategy");
            if (node == null || node.isNull() || !node.isTextual()) return null;
            String text = node.asText();
            return text == null || text.isBlank() ? null : text;
        } catch (JsonProcessingException ignored) {
            return null;
        }
    }

    private static String resource(String name) {
        try (InputStream stream = SQLiteControlPlanePersistence.class.getClassLoader().getResourceAsStream(name)) {
            if (stream == null) throw new MigrationException("database migration resource is missing");
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException failure) {
            throw new MigrationException("database migration resource could not be read", failure);
        }
    }

    private static Path controlledDatabasePath(Path requested, Path allowedRoot) {
        Objects.requireNonNull(requested, "databasePath");
        Objects.requireNonNull(allowedRoot, "allowedRoot");
        try {
            Path root = allowedRoot.toAbsolutePath().normalize().toRealPath();
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("allowedRoot must be a real directory");
            }
            Path normalized = requested.toAbsolutePath().normalize();
            if (!normalized.startsWith(root)) {
                throw new IllegalArgumentException("database path must remain under allowedRoot");
            }
            Path parent = normalized.getParent();
            if (parent == null) throw new IllegalArgumentException("database path requires a parent directory");
            Files.createDirectories(parent);
            Path realParent = parent.toRealPath();
            if (!realParent.startsWith(root)) {
                throw new IllegalArgumentException("database parent resolves outside allowedRoot");
            }
            Path result = realParent.resolve(normalized.getFileName()).normalize();
            if (Files.exists(result, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(result)) {
                throw new IllegalArgumentException("database path must not be a symbolic link");
            }
            if (Files.exists(result, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(result, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("database path must be a regular file");
            }
            return result;
        } catch (IOException failure) {
            throw new IllegalArgumentException("database path could not be secured", failure);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static PersistenceException databaseFailure(String message, SQLException failure) {
        return new PersistenceException(message, failure);
    }

    public record ProjectData(String projectId, String name, String status, String createdAt,
                              String updatedAt, String deletedAt) { }
    public record ArtifactData(String projectId, ArtifactDescriptor descriptor) { }
    public record ArtifactUploadData(String uploadId, String projectId, String fileName, long sizeBytes,
                                     String sha256, long nextOffset, String createdAt, String expiresAt) { }
    public record OperatorData(String operatorId, String username, OperatorRole role,
                               String createdAt, String updatedAt) { }
    public record ProviderData(String providerId, String name, ProviderKind kind, String baseUrl,
                               String model, boolean enabled, String createdAt, String updatedAt,
                               boolean hasCredential) { }
    public record StoredSecret(SecretScope scope, EncryptedSecret encrypted) { }
    public record RoleBindingData(String projectId, AgentRole role, String providerId,
                                  String model, String updatedAt, String promptZh, String promptEn) {
        public RoleBindingData(String projectId, AgentRole role, String providerId,
                               String model, String updatedAt) {
            this(projectId, role, providerId, model, updatedAt, null, null);
        }
    }
    public record AiJobData(String aiJobId, String workspaceId, String projectId, String scanId,
                            String artifactDigest, AgentRole role, String providerId, String model,
                            String policySnapshotJson, boolean authorized, String status,
                            String stopReason, String stagesJson, String providerRequestId,
                            long elapsedMillis, int rounds, String toolSummaryJson,
                            String conclusionJson, String createdAt, String updatedAt) { }
    public record AiJobEventData(String aiJobId, long sequence, String workspaceId, String projectId,
                                 String stage, String status, String providerRequestSummary,
                                 String providerResultSummary, String toolCallName,
                                 String toolArgumentsSummary, String toolResultStatus,
                                 String modelInferenceSummary, String failureDiagnostic,
                                 String createdAt) { }
    public record AuditData(String auditEventId, String projectId, String operatorId, String action,
                            String targetType, String targetId, String outcome, String detailsJson,
                            String createdAt) { }
    public record IdempotencyData(String scope, String key, String payloadHash, String resultRef,
                                  String resultJson, String createdAt) { }
    public record PipelineRunData(String scanId, String projectId, String actorId,
                                  String outputLanguage, boolean armed, String nextStage,
                                  String updatedAt) { }
    public record ProbePlanData(String taskId, String projectId, String artifactDigest,
                                String scanId, String targetEntryId, String candidateInputsJson,
                                int maxRequests, String planHash, String createdAt) { }
    public record ExperimentPlanData(String planId, String scanId, String projectId,
                                     String artifactDigest, String payloadJson, String createdAt,
                                     String fuzzStrategyJson) {
        public ExperimentPlanData(String planId, String scanId, String projectId,
                                  String artifactDigest, String payloadJson, String createdAt) {
            this(planId, scanId, projectId, artifactDigest, payloadJson, createdAt, null);
        }
    }
    public record Snapshot(List<ProjectData> projects, List<ArtifactData> artifacts,
                           List<ControlPlaneStore.ScanRecord> scans) {
        public Snapshot {
            projects = List.copyOf(projects);
            artifacts = List.copyOf(artifacts);
            scans = List.copyOf(scans);
        }
    }
    public record WorkerState(List<TaskSnapshot> tasks, List<InMemoryTraceStore.StoredTrace> traces) {
        public WorkerState {
            tasks = List.copyOf(tasks);
            traces = List.copyOf(traces);
        }
        public static WorkerState empty() { return new WorkerState(List.of(), List.of()); }
    }

    public static class PersistenceException extends RuntimeException {
        public PersistenceException(String message) { super(message); }
        public PersistenceException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class MigrationException extends PersistenceException {
        public MigrationException(String message) { super(message); }
        public MigrationException(String message, Throwable cause) { super(message, cause); }
    }

    @FunctionalInterface
    private interface SqlWork {
        void run(Connection connection) throws SQLException;
    }
}
