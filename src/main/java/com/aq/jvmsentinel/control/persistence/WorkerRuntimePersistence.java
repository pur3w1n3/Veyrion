package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Worker 状态、SSE、幂等键、流水线运行与 Probe 计划的持久化。
 */
final class WorkerRuntimePersistence {
    private static final int IDEMPOTENCY_BUSY_RETRIES = 5;
    private static final long IDEMPOTENCY_BUSY_BACKOFF_MILLIS = 25L;

    private final PersistenceSupport support;

    WorkerRuntimePersistence(PersistenceSupport support) {
        this.support = support;
    }

    List<SQLiteControlPlanePersistence.IdempotencyData> loadIdempotency() {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT scope,idempotency_key,payload_hash,result_ref,result_json,created_at "
                             + "FROM control_plane_idempotency ORDER BY created_at,scope,idempotency_key")) {
            List<SQLiteControlPlanePersistence.IdempotencyData> result = new ArrayList<>();
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.IdempotencyData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6)));
                }
            }
            if (result.size() > 50_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent idempotency limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load persistent idempotency records", failure);
        }
    }

    /** 插入不可变记录，或返回同一 scope/key 已提交的记录。 */
    SQLiteControlPlanePersistence.IdempotencyData putIdempotency(
            SQLiteControlPlanePersistence.IdempotencyData candidate) {
        Objects.requireNonNull(candidate, "candidate");
        SQLException lastBusy = null;
        for (int attempt = 1; attempt <= IDEMPOTENCY_BUSY_RETRIES; attempt++) {
            try {
                return putIdempotencyOnce(candidate);
            } catch (SQLiteControlPlanePersistence.PersistenceException persistenceFailure) {
                throw persistenceFailure;
            } catch (SQLException failure) {
                lastBusy = failure;
                if (!PersistenceSupport.isSqliteBusyOrLocked(failure) || attempt >= IDEMPOTENCY_BUSY_RETRIES) {
                    throw PersistenceSupport.databaseFailure("could not persist idempotency record", failure);
                }
                PersistenceSupport.sleepQuietly(IDEMPOTENCY_BUSY_BACKOFF_MILLIS * attempt);
            }
        }
        throw PersistenceSupport.databaseFailure("could not persist idempotency record",
                lastBusy != null ? lastBusy : new SQLException("idempotency persist retries exhausted"));
    }

    List<SQLiteControlPlanePersistence.PipelineRunData> loadPipelineRuns() {
        try (Connection connection = support.open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT scan_id,project_id,actor_id,output_language,armed,next_stage,updated_at,"
                             + "pipeline_run_id,stage_attempt_id,expected_job_id,expected_task_id,stop_reason "
                             + "FROM audit_pipeline_runs ORDER BY updated_at,scan_id")) {
            List<SQLiteControlPlanePersistence.PipelineRunData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new SQLiteControlPlanePersistence.PipelineRunData(
                        rows.getString(1), rows.getString(2), rows.getString(3), rows.getString(4),
                        rows.getInt(5) != 0, rows.getString(6), rows.getString(7),
                        rows.getString(8), rows.getString(9), rows.getString(10), rows.getString(11),
                        rows.getString(12)));
            }
            if (result.size() > 20_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent pipeline run limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load pipeline runs", failure);
        }
    }

    void savePipelineRun(SQLiteControlPlanePersistence.PipelineRunData run) {
        Objects.requireNonNull(run, "run");
        support.transaction("could not persist pipeline run", connection -> PersistenceSupport.update(connection,
                "INSERT INTO audit_pipeline_runs(scan_id,project_id,actor_id,output_language,armed,next_stage,"
                        + "updated_at,pipeline_run_id,stage_attempt_id,expected_job_id,expected_task_id,stop_reason) "
                        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET "
                        + "project_id=excluded.project_id,actor_id=excluded.actor_id,"
                        + "output_language=excluded.output_language,armed=excluded.armed,"
                        + "next_stage=excluded.next_stage,updated_at=excluded.updated_at,"
                        + "pipeline_run_id=excluded.pipeline_run_id,stage_attempt_id=excluded.stage_attempt_id,"
                        + "expected_job_id=excluded.expected_job_id,expected_task_id=excluded.expected_task_id,"
                        + "stop_reason=excluded.stop_reason",
                run.scanId(), run.projectId(), run.actorId(), run.outputLanguage(), run.armed() ? 1 : 0,
                run.nextStage(), run.updatedAt(), run.pipelineRunId(), run.stageAttemptId(),
                run.expectedJobId(), run.expectedTaskId(), run.stopReason()));
    }

    /**
     * CAS 游标推进：仅 armed 且 scan/run/attempt 与 expected 资源匹配的行可前进。
     * 外来、过期、重复或迟到写入返回 false。
     */
    boolean compareAndAdvancePipelineRun(SQLiteControlPlanePersistence.PipelineRunData expected,
                                           SQLiteControlPlanePersistence.PipelineRunData next) {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(next, "next");
        if (!expected.scanId().equals(next.scanId())) {
            throw new SQLiteControlPlanePersistence.PersistenceException("pipeline CAS scanId mismatch");
        }
        try (Connection connection = support.open()) {
            connection.setAutoCommit(true);
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE audit_pipeline_runs SET project_id=?,actor_id=?,output_language=?,armed=?,"
                            + "next_stage=?,updated_at=?,pipeline_run_id=?,stage_attempt_id=?,"
                            + "expected_job_id=?,expected_task_id=?,stop_reason=? "
                            + "WHERE scan_id=? AND armed=1 "
                            + "AND pipeline_run_id IS NOT NULL AND pipeline_run_id=? "
                            + "AND stage_attempt_id IS NOT NULL AND stage_attempt_id=? "
                            + "AND next_stage=? "
                            + "AND ((? IS NULL AND expected_job_id IS NULL) OR expected_job_id=?) "
                            + "AND ((? IS NULL AND expected_task_id IS NULL) OR expected_task_id=?)")) {
                int index = 1;
                statement.setObject(index++, next.projectId());
                statement.setObject(index++, next.actorId());
                statement.setObject(index++, next.outputLanguage());
                statement.setObject(index++, next.armed() ? 1 : 0);
                statement.setObject(index++, next.nextStage());
                statement.setObject(index++, next.updatedAt());
                statement.setObject(index++, next.pipelineRunId());
                statement.setObject(index++, next.stageAttemptId());
                statement.setObject(index++, next.expectedJobId());
                statement.setObject(index++, next.expectedTaskId());
                statement.setObject(index++, next.stopReason());
                statement.setObject(index++, expected.scanId());
                statement.setObject(index++, expected.pipelineRunId());
                statement.setObject(index++, expected.stageAttemptId());
                statement.setObject(index++, expected.nextStage());
                statement.setObject(index++, expected.expectedJobId());
                statement.setObject(index++, expected.expectedJobId());
                statement.setObject(index++, expected.expectedTaskId());
                statement.setObject(index, expected.expectedTaskId());
                return statement.executeUpdate() == 1;
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not CAS-advance pipeline run", failure);
        }
    }

    List<SQLiteControlPlanePersistence.ProbePlanData> loadProbePlans() {
        try (Connection connection = support.open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT task_id,project_id,artifact_digest,scan_id,target_entry_id,candidate_inputs_json,"
                             + "max_requests,plan_hash,created_at,payload_json "
                             + "FROM dynamic_probe_plans ORDER BY created_at,task_id")) {
            List<SQLiteControlPlanePersistence.ProbePlanData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new SQLiteControlPlanePersistence.ProbePlanData(
                        rows.getString(1), rows.getString(2), rows.getString(3),
                        rows.getString(4), rows.getString(5), rows.getString(6), rows.getInt(7),
                        rows.getString(8), rows.getString(9), rows.getString(10)));
            }
            if (result.size() > 20_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent probe plan limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load probe plans", failure);
        }
    }

    void saveProbePlan(SQLiteControlPlanePersistence.ProbePlanData plan) {
        Objects.requireNonNull(plan, "plan");
        support.transaction("could not persist probe plan", connection -> PersistenceSupport.update(connection,
                "INSERT INTO dynamic_probe_plans(task_id,project_id,artifact_digest,scan_id,target_entry_id,"
                        + "candidate_inputs_json,max_requests,plan_hash,created_at,payload_json) "
                        + "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET "
                        + "candidate_inputs_json=excluded.candidate_inputs_json,"
                        + "max_requests=excluded.max_requests,plan_hash=excluded.plan_hash,"
                        + "payload_json=excluded.payload_json",
                plan.taskId(), plan.projectId(), plan.artifactDigest(), plan.scanId(), plan.targetEntryId(),
                plan.candidateInputsJson(), plan.maxRequests(), plan.planHash(), plan.createdAt(),
                plan.payloadJson()));
    }

    List<VersionedEvent> loadSseEvents() {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT event_id,scan_id,event_type,schema_version,occurred_at,project_id,artifact_digest,"
                             + "task_id,idempotency_scope,idempotency_value,payload_json FROM sse_events ORDER BY rowid");
             ResultSet rows = statement.executeQuery()) {
            List<VersionedEvent> result = new ArrayList<>();
            while (rows.next()) {
                EventContext context = rows.getString(6) == null ? null : new EventContext(
                        rows.getString(6), rows.getString(7), rows.getString(2), rows.getString(8));
                result.add(new VersionedEvent(rows.getString(1), rows.getString(3), rows.getInt(4),
                        Instant.parse(rows.getString(5)), context,
                        new IdempotencyKey(rows.getString(9), rows.getString(10)), rows.getString(11)));
            }
            if (result.size() > 100_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent SSE event limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof SQLiteControlPlanePersistence.PersistenceException persistenceFailure) {
                throw persistenceFailure;
            }
            throw PersistenceSupport.databaseFailure("could not load persistent SSE events",
                    failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    void persistSseEvent(String scanId, VersionedEvent event) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(event, "event");
        support.transaction("could not persist SSE event", connection -> {
            EventContext context = event.context();
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT OR IGNORE INTO sse_events(event_id,scan_id,event_type,schema_version,occurred_at,"
                            + "project_id,artifact_digest,task_id,idempotency_scope,idempotency_value,payload_json) "
                            + "VALUES(?,?,?,?,?,?,?,?,?,?,?)")) {
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
                    "DELETE FROM sse_events WHERE scan_id=? AND event_id NOT IN "
                            + "(SELECT event_id FROM sse_events WHERE scan_id=? ORDER BY rowid DESC LIMIT 256)")) {
                trim.setString(1, scanId);
                trim.setString(2, scanId);
                trim.executeUpdate();
            }
        });
    }

    SQLiteControlPlanePersistence.WorkerState loadWorkerState() {
        try (Connection connection = support.open()) {
            List<TaskSnapshot> tasks = new ArrayList<>();
            try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                    "SELECT project_id,artifact_digest,scan_id,task_id,schema_version,target_entry_id,authorized,"
                            + "max_wall_clock_seconds,max_cpu_millis,max_memory_bytes,max_disk_bytes,max_trace_bytes,"
                            + "network_mode,network_allowlist,required_capability,lifecycle,lease_id,lease_worker_id,"
                            + "lease_capability,lease_issued_at,lease_heartbeat_at,lease_expires_at,checkpoint_id,"
                            + "checkpoint_trace_sequence,checkpoint_trace_head_digest,checkpoint_created_at,stop_reason,"
                            + "failure_code,updated_at FROM worker_tasks ORDER BY rowid")) {
                while (rows.next()) {
                    tasks.add(readTask(rows));
                }
            }
            if (tasks.size() > 20_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent worker task limit exceeded");
            }
            // 仅为可恢复任务加载 chunk。终态任务证据在 path_runs/path_traces；
            // 加载全部历史 worker_trace_chunk 会阻塞控制面启动。
            Map<TaskScope, ResourceBudget> budgets = new LinkedHashMap<>();
            Set<TaskScope> resumable = new java.util.HashSet<>();
            for (TaskSnapshot task : tasks) {
                budgets.put(task.scope(), task.spec().resourceBudget());
                if (isResumableWorkerLifecycle(task.lifecycle())) {
                    resumable.add(task.scope());
                }
            }
            List<InMemoryTraceStore.StoredTrace> traces = new ArrayList<>();
            long bytes = 0;
            if (!resumable.isEmpty()) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT c.project_id,c.artifact_digest,c.scan_id,c.task_id,c.sequence,c.idempotency_key,"
                                + "c.schema_version,c.previous_digest,c.emitted_at,c.payload,c.digest "
                                + "FROM worker_trace_chunks c "
                                + "INNER JOIN worker_tasks t ON c.project_id=t.project_id "
                                + "AND c.artifact_digest=t.artifact_digest AND c.scan_id=t.scan_id "
                                + "AND c.task_id=t.task_id "
                                + "WHERE t.lifecycle IN ('QUEUED','LEASED','RUNNING','PAUSED') "
                                + "ORDER BY c.project_id,c.artifact_digest,c.scan_id,c.task_id,c.sequence");
                     ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        TaskScope scope = new TaskScope(rows.getString(1), rows.getString(2),
                                rows.getString(3), rows.getString(4));
                        if (!budgets.containsKey(scope) || !resumable.contains(scope)) {
                            throw new SQLiteControlPlanePersistence.PersistenceException(
                                    "trace has no resumable task scope");
                        }
                        byte[] payload = rows.getBytes(10);
                        bytes = Math.addExact(bytes, payload.length);
                        if (bytes > 1_073_741_824L) {
                            throw new SQLiteControlPlanePersistence.PersistenceException(
                                    "persistent trace byte limit exceeded");
                        }
                        TraceChunk chunk = new TraceChunk(rows.getInt(7), scope, rows.getLong(5),
                                rows.getString(8), Instant.parse(rows.getString(9)), payload,
                                rows.getString(11));
                        if (payload.length > budgets.get(scope).maxTraceBytes()) {
                            throw new SQLiteControlPlanePersistence.PersistenceException(
                                    "trace exceeds task byte budget");
                        }
                        traces.add(new InMemoryTraceStore.StoredTrace(rows.getString(6), chunk));
                    }
                }
            }
            if (traces.size() > 100_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent trace chunk limit exceeded");
            }
            return new SQLiteControlPlanePersistence.WorkerState(tasks, traces);
        } catch (SQLException | ArithmeticException failure) {
            throw PersistenceSupport.databaseFailure("could not load persistent Worker state",
                    failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    void persistWorkerTask(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        support.transaction("could not persist Worker task", connection -> {
            WorkerTaskSpec spec = snapshot.spec();
            NetworkPolicy network = spec.networkPolicy();
            WorkerLease lease = snapshot.lease();
            TaskCheckpoint checkpoint = snapshot.checkpoint();
            PersistenceSupport.update(connection,
                    "INSERT INTO worker_tasks(project_id,artifact_digest,scan_id,task_id,schema_version,target_entry_id,authorized,"
                            + "max_wall_clock_seconds,max_cpu_millis,max_memory_bytes,max_disk_bytes,max_trace_bytes,network_mode,network_allowlist,"
                            + "required_capability,lifecycle,lease_id,lease_worker_id,lease_capability,lease_issued_at,lease_heartbeat_at,lease_expires_at,"
                            + "checkpoint_id,checkpoint_trace_sequence,checkpoint_trace_head_digest,checkpoint_created_at,stop_reason,failure_code,updated_at) "
                            + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                            + "ON CONFLICT(project_id,artifact_digest,scan_id,task_id) DO UPDATE SET schema_version=excluded.schema_version,target_entry_id=excluded.target_entry_id,"
                            + "authorized=excluded.authorized,max_wall_clock_seconds=excluded.max_wall_clock_seconds,max_cpu_millis=excluded.max_cpu_millis,max_memory_bytes=excluded.max_memory_bytes,"
                            + "max_disk_bytes=excluded.max_disk_bytes,max_trace_bytes=excluded.max_trace_bytes,network_mode=excluded.network_mode,network_allowlist=excluded.network_allowlist,"
                            + "required_capability=excluded.required_capability,lifecycle=excluded.lifecycle,lease_id=excluded.lease_id,lease_worker_id=excluded.lease_worker_id,"
                            + "lease_capability=excluded.lease_capability,lease_issued_at=excluded.lease_issued_at,lease_heartbeat_at=excluded.lease_heartbeat_at,lease_expires_at=excluded.lease_expires_at,"
                            + "checkpoint_id=excluded.checkpoint_id,checkpoint_trace_sequence=excluded.checkpoint_trace_sequence,checkpoint_trace_head_digest=excluded.checkpoint_trace_head_digest,"
                            + "checkpoint_created_at=excluded.checkpoint_created_at,stop_reason=excluded.stop_reason,failure_code=excluded.failure_code,updated_at=excluded.updated_at",
                    spec.projectId(), spec.artifactDigest(), spec.scanId(), spec.taskId(), snapshot.schemaVersion(),
                    spec.targetEntryId(), spec.authorized() ? 1 : 0,
                    spec.resourceBudget().maxWallClockSeconds(), spec.resourceBudget().maxCpuMillis(),
                    spec.resourceBudget().maxMemoryBytes(), spec.resourceBudget().maxDiskBytes(),
                    spec.resourceBudget().maxTraceBytes(),
                    network.mode().name(), String.join("\n", network.allowlist()), spec.requiredCapability().name(),
                    snapshot.lifecycle().name(),
                    lease == null ? null : lease.leaseId(), lease == null ? null : lease.workerId(),
                    lease == null ? null : lease.capability().name(),
                    lease == null ? null : lease.issuedAt().toString(),
                    lease == null ? null : lease.heartbeatAt().toString(),
                    lease == null ? null : lease.expiresAt().toString(),
                    checkpoint == null ? null : checkpoint.checkpointId(),
                    checkpoint == null ? null : checkpoint.traceSequence(),
                    checkpoint == null ? null : checkpoint.traceHeadDigest(),
                    checkpoint == null ? null : checkpoint.createdAt().toString(),
                    snapshot.stopReason() == null ? null : snapshot.stopReason().name(),
                    snapshot.failureCode(), snapshot.updatedAt().toString());
        });
    }

    void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 128
                || idempotencyKey.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("idempotencyKey is invalid");
        }
        Objects.requireNonNull(chunk, "chunk");
        support.transaction("could not persist Worker trace", connection -> {
            TaskScope scope = chunk.scope();
            try (PreparedStatement existing = connection.prepareStatement(
                    "SELECT sequence,schema_version,previous_digest,emitted_at,payload,digest "
                            + "FROM worker_trace_chunks WHERE project_id=? AND artifact_digest=? AND scan_id=? "
                            + "AND task_id=? AND idempotency_key=?")) {
                existing.setString(1, scope.projectId());
                existing.setString(2, scope.artifactDigest());
                existing.setString(3, scope.scanId());
                existing.setString(4, scope.taskId());
                existing.setString(5, idempotencyKey);
                try (ResultSet rows = existing.executeQuery()) {
                    if (rows.next()) {
                        TraceChunk prior = new TraceChunk(rows.getInt(2), scope, rows.getLong(1),
                                rows.getString(3), Instant.parse(rows.getString(4)), rows.getBytes(5),
                                rows.getString(6));
                        if (!prior.equals(chunk)) {
                            throw new IllegalStateException("idempotency key payload conflict");
                        }
                        return;
                    }
                }
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT sequence,digest FROM worker_trace_chunks WHERE project_id=? AND artifact_digest=? "
                            + "AND scan_id=? AND task_id=? ORDER BY sequence DESC LIMIT 1")) {
                statement.setString(1, scope.projectId());
                statement.setString(2, scope.artifactDigest());
                statement.setString(3, scope.scanId());
                statement.setString(4, scope.taskId());
                try (ResultSet rows = statement.executeQuery()) {
                    boolean found = rows.next();
                    long sequence = found ? rows.getLong(1) + 1 : 0;
                    String previous = found ? rows.getString(2) : null;
                    if (chunk.sequence() != sequence || !Objects.equals(chunk.previousDigest(), previous)) {
                        throw new IllegalStateException("trace chain is not contiguous");
                    }
                }
            }
            PersistenceSupport.update(connection,
                    "INSERT INTO worker_trace_chunks(project_id,artifact_digest,scan_id,task_id,sequence,idempotency_key,schema_version,previous_digest,emitted_at,payload,digest) "
                            + "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    scope.projectId(), scope.artifactDigest(), scope.scanId(), scope.taskId(), chunk.sequence(),
                    idempotencyKey, chunk.schemaVersion(), chunk.previousDigest(), chunk.emittedAt().toString(),
                    chunk.payload(), chunk.digest());
        });
    }

    private SQLiteControlPlanePersistence.IdempotencyData putIdempotencyOnce(
            SQLiteControlPlanePersistence.IdempotencyData candidate) throws SQLException {
        try (Connection connection = support.open()) {
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
                                    if (!found.next()) {
                                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                                "persistent idempotency limit exceeded");
                                    }
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
                SQLiteControlPlanePersistence.IdempotencyData stored;
                try (PreparedStatement select = connection.prepareStatement(
                        "SELECT scope,idempotency_key,payload_hash,result_ref,result_json,created_at "
                                + "FROM control_plane_idempotency WHERE scope=? AND idempotency_key=?")) {
                    select.setString(1, candidate.scope());
                    select.setString(2, candidate.key());
                    try (ResultSet rows = select.executeQuery()) {
                        if (!rows.next()) {
                            throw new SQLException("idempotency record was not committed");
                        }
                        stored = new SQLiteControlPlanePersistence.IdempotencyData(
                                rows.getString(1), rows.getString(2), rows.getString(3),
                                rows.getString(4), rows.getString(5), rows.getString(6));
                    }
                }
                connection.commit();
                return stored;
            } catch (Exception failure) {
                PersistenceSupport.rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new SQLException("idempotency transaction failed", failure);
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    /** 控制面重启后仍可能追加或恢复 trace 的任务。 */
    private static boolean isResumableWorkerLifecycle(TaskLifecycle lifecycle) {
        return lifecycle == TaskLifecycle.QUEUED
                || lifecycle == TaskLifecycle.LEASED
                || lifecycle == TaskLifecycle.RUNNING
                || lifecycle == TaskLifecycle.PAUSED;
    }

    private TaskSnapshot readTask(ResultSet rows) throws SQLException {
        TaskScope scope = new TaskScope(rows.getString(1), rows.getString(2),
                rows.getString(3), rows.getString(4));
        int schemaVersion = rows.getInt(5);
        PayloadSchemaGuard.requireColumnSchemaVersion(schemaVersion, "worker_task " + scope.taskId());
        NetworkPolicy network = new NetworkPolicy(NetworkMode.valueOf(rows.getString(13)),
                rows.getString(14).isEmpty() ? List.of() : List.of(rows.getString(14).split("\\n", -1)));
        WorkerTaskSpec spec = new WorkerTaskSpec(schemaVersion, scope.projectId(), scope.artifactDigest(),
                scope.scanId(), scope.taskId(), rows.getString(6), rows.getInt(7) != 0,
                new ResourceBudget(rows.getLong(8), rows.getLong(9), rows.getLong(10), rows.getLong(11),
                        rows.getLong(12)),
                network, WorkerCapability.valueOf(rows.getString(15)));
        WorkerLease lease = rows.getString(17) == null ? null : new WorkerLease(schemaVersion, scope,
                rows.getString(17), rows.getString(18), WorkerCapability.valueOf(rows.getString(19)),
                Instant.parse(rows.getString(20)), Instant.parse(rows.getString(21)),
                Instant.parse(rows.getString(22)));
        TaskCheckpoint checkpoint = rows.getString(23) == null ? null : new TaskCheckpoint(schemaVersion, scope,
                rows.getString(23), rows.getLong(24), rows.getString(25), Instant.parse(rows.getString(26)));
        return new TaskSnapshot(schemaVersion, spec, TaskLifecycle.valueOf(rows.getString(16)), lease, checkpoint,
                rows.getString(27) == null ? null : StopReason.valueOf(rows.getString(27)),
                rows.getString(28), Instant.parse(rows.getString(29)));
    }
}
