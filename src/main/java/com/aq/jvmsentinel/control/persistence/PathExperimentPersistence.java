package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.control.ApiDtos;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Path 运行、轨迹、Trace 计划、World Pack 与实验计划的持久化。
 */
final class PathExperimentPersistence {
    private final PersistenceSupport support;

    PathExperimentPersistence(PersistenceSupport support) {
        this.support = support;
    }

    List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlans() {
        try (Connection connection = support.open(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT plan_id,scan_id,project_id,artifact_digest,payload_json,created_at,"
                             + "fuzz_strategy_json FROM experiment_plans ORDER BY created_at,plan_id")) {
            List<SQLiteControlPlanePersistence.ExperimentPlanData> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new SQLiteControlPlanePersistence.ExperimentPlanData(
                        rows.getString(1), rows.getString(2), rows.getString(3),
                        rows.getString(4), rows.getString(5), rows.getString(6),
                        rows.getString(7)));
            }
            if (result.size() > 20_000) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent experiment plan limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load experiment plans", failure);
        }
    }

    List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT plan_id,scan_id,project_id,artifact_digest,payload_json,created_at,"
                             + "fuzz_strategy_json FROM experiment_plans WHERE scan_id=? "
                             + "ORDER BY created_at,plan_id")) {
            statement.setString(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<SQLiteControlPlanePersistence.ExperimentPlanData> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.ExperimentPlanData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6),
                            rows.getString(7)));
                }
                if (result.size() > 256) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "per-scan experiment plan limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load experiment plans for scan", failure);
        }
    }

    void saveExperimentPlan(SQLiteControlPlanePersistence.ExperimentPlanData plan) {
        Objects.requireNonNull(plan, "plan");
        String fuzz = plan.fuzzStrategyJson();
        if ((fuzz == null || fuzz.isBlank()) && plan.payloadJson() != null) {
            fuzz = support.extractFuzzStrategyJson(plan.payloadJson());
        }
        String fuzzColumn = fuzz == null || fuzz.isBlank() ? null : fuzz;
        String finalFuzz = fuzzColumn;
        support.transaction("could not persist experiment plan", connection -> PersistenceSupport.update(connection,
                "INSERT INTO experiment_plans(plan_id,scan_id,project_id,artifact_digest,payload_json,"
                        + "created_at,fuzz_strategy_json) "
                        + "VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,plan_id) DO UPDATE SET "
                        + "payload_json=excluded.payload_json,created_at=excluded.created_at,"
                        + "fuzz_strategy_json=excluded.fuzz_strategy_json",
                plan.planId(), plan.scanId(), plan.projectId(), plan.artifactDigest(),
                plan.payloadJson(), plan.createdAt(), finalFuzz));
    }

    List<ApiDtos.PathRunDto> loadPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = support.open();
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
                    if (result.size() > 50_000) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "persistent path run limit exceeded");
                    }
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load path runs", failure);
        }
    }

    List<ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        Objects.requireNonNull(taskId, "taskId");
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT path_run_id,payload_json FROM path_runs WHERE task_id=? "
                             + "ORDER BY created_at,path_run_id")) {
            statement.setString(1, taskId);
            try (ResultSet rows = statement.executeQuery()) {
                List<ApiDtos.PathRunDto> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(decodePathRun(rows.getString(1), rows.getString(2)));
                    if (result.size() > 20_000) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "persistent path run limit exceeded");
                    }
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load path runs for task", failure);
        }
    }

    void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                String taskId, List<ApiDtos.PathRunDto> pathRuns, String createdAt) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(taskId, "taskId");
        Objects.requireNonNull(createdAt, "createdAt");
        List<ApiDtos.PathRunDto> runs = List.copyOf(pathRuns == null ? List.of() : pathRuns);
        if (runs.size() > 20_000) {
            throw new SQLiteControlPlanePersistence.PersistenceException("path run batch limit exceeded");
        }
        support.transaction("could not persist path runs", connection -> {
            // 首次写入时 DELETE 可能影响 0 行；勿用要求恰好一行的 update()。
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM path_runs WHERE task_id=?")) {
                delete.setString(1, taskId);
                delete.executeUpdate();
            }
            for (ApiDtos.PathRunDto run : runs) {
                if (!scanId.equals(run.scanId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException("path run scan scope mismatch");
                }
                PersistenceSupport.update(connection,
                        "INSERT INTO path_runs(path_run_id,project_id,artifact_digest,scan_id,task_id,payload_json,created_at) "
                                + "VALUES(?,?,?,?,?,?,?)",
                        run.pathRunId(), projectId, artifactDigest, scanId, taskId, support.write(run), createdAt);
            }
        });
    }

    void saveTracePlan(SQLiteControlPlanePersistence.TracePlanData plan) {
        Objects.requireNonNull(plan, "plan");
        support.transaction("could not persist trace plan", connection -> PersistenceSupport.update(connection,
                "INSERT INTO trace_plans(trace_plan_id,scan_id,project_id,artifact_digest,entry_ref,payload_json,created_at) "
                        + "VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,trace_plan_id) DO UPDATE SET "
                        + "payload_json=excluded.payload_json,created_at=excluded.created_at",
                plan.tracePlanId(), plan.scanId(), plan.projectId(), plan.artifactDigest(),
                plan.entryRef(), plan.payloadJson(), plan.createdAt()));
    }

    List<SQLiteControlPlanePersistence.TracePlanData> loadTracePlansForScan(String scanId) {
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT trace_plan_id,scan_id,project_id,artifact_digest,entry_ref,payload_json,created_at "
                             + "FROM trace_plans WHERE scan_id=? ORDER BY created_at,trace_plan_id")) {
            statement.setString(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<SQLiteControlPlanePersistence.TracePlanData> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.TracePlanData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6), rows.getString(7)));
                }
                if (result.size() > 512) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "per-scan trace plan limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load trace plans for scan", failure);
        }
    }

    void saveWorldPack(SQLiteControlPlanePersistence.WorldPackData pack) {
        Objects.requireNonNull(pack, "pack");
        support.transaction("could not persist world pack", connection -> PersistenceSupport.update(connection,
                "INSERT INTO world_packs(world_pack_id,scan_id,project_id,artifact_digest,dependency_mode,payload_json,created_at) "
                        + "VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,world_pack_id) DO UPDATE SET "
                        + "dependency_mode=excluded.dependency_mode,payload_json=excluded.payload_json,"
                        + "created_at=excluded.created_at",
                pack.worldPackId(), pack.scanId(), pack.projectId(), pack.artifactDigest(),
                pack.dependencyMode(), pack.payloadJson(), pack.createdAt()));
    }

    List<SQLiteControlPlanePersistence.WorldPackData> loadWorldPacksForScan(String scanId) {
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT world_pack_id,scan_id,project_id,artifact_digest,dependency_mode,payload_json,created_at "
                             + "FROM world_packs WHERE scan_id=? ORDER BY created_at,world_pack_id")) {
            statement.setString(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<SQLiteControlPlanePersistence.WorldPackData> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.WorldPackData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6), rows.getString(7)));
                }
                if (result.size() > 64) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "per-scan world pack limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load world packs for scan", failure);
        }
    }

    void savePathTrace(SQLiteControlPlanePersistence.PathTraceData trace) {
        Objects.requireNonNull(trace, "trace");
        support.transaction("could not persist path trace", connection -> PersistenceSupport.update(connection,
                "INSERT INTO path_traces(path_trace_id,path_run_id,scan_id,project_id,artifact_digest,task_id,"
                        + "experiment_plan_id,trace_plan_id,world_pack_id,posture_kind,exit_reason,legacy_incomplete,"
                        + "payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                        + "ON CONFLICT(path_trace_id) DO UPDATE SET payload_json=excluded.payload_json,"
                        + "exit_reason=excluded.exit_reason,legacy_incomplete=excluded.legacy_incomplete,"
                        + "created_at=excluded.created_at",
                trace.pathTraceId(), trace.pathRunId(), trace.scanId(), trace.projectId(),
                trace.artifactDigest(), trace.taskId(), trace.experimentPlanId(), trace.tracePlanId(),
                trace.worldPackId(), trace.postureKind(), trace.exitReason(), trace.legacyIncomplete() ? 1 : 0,
                trace.payloadJson(), trace.createdAt()));
    }

    List<SQLiteControlPlanePersistence.PathTraceData> loadPathTracesForScan(
            String projectId, String artifactDigest, String scanId) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT path_trace_id,path_run_id,scan_id,project_id,artifact_digest,task_id,"
                             + "experiment_plan_id,trace_plan_id,world_pack_id,posture_kind,exit_reason,"
                             + "legacy_incomplete,payload_json,created_at FROM path_traces "
                             + "WHERE project_id=? AND artifact_digest=? AND scan_id=? "
                             + "ORDER BY created_at,path_trace_id")) {
            statement.setString(1, projectId);
            statement.setString(2, artifactDigest);
            statement.setString(3, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                List<SQLiteControlPlanePersistence.PathTraceData> result = new ArrayList<>();
                while (rows.next()) {
                    result.add(new SQLiteControlPlanePersistence.PathTraceData(
                            rows.getString(1), rows.getString(2), rows.getString(3), rows.getString(4),
                            rows.getString(5), rows.getString(6), rows.getString(7), rows.getString(8),
                            rows.getString(9), rows.getString(10), rows.getString(11),
                            rows.getInt(12) != 0, rows.getString(13), rows.getString(14)));
                }
                if (result.size() > 50_000) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "persistent path trace limit exceeded");
                }
                return List.copyOf(result);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load path traces for scan", failure);
        }
    }

    void replacePathTracesForTask(String projectId, String artifactDigest, String scanId,
                                  String taskId, List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                  String createdAt) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(taskId, "taskId");
        Objects.requireNonNull(createdAt, "createdAt");
        List<SQLiteControlPlanePersistence.PathTraceData> rows =
                List.copyOf(traces == null ? List.of() : traces);
        if (rows.size() > 20_000) {
            throw new SQLiteControlPlanePersistence.PersistenceException("path trace batch limit exceeded");
        }
        support.transaction("could not persist path traces", connection -> {
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM path_traces WHERE task_id=?")) {
                delete.setString(1, taskId);
                delete.executeUpdate();
            }
            for (SQLiteControlPlanePersistence.PathTraceData trace : rows) {
                if (!scanId.equals(trace.scanId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException("path trace scan scope mismatch");
                }
                savePathTrace(connection, trace, createdAt);
            }
        });
    }

    private ApiDtos.PathRunDto decodePathRun(String pathRunId, String payloadJson) {
        try {
            PayloadSchemaGuard.requireJsonSchemaVersion(
                    support.mapper(), payloadJson, "path_run " + pathRunId);
            ApiDtos.PathRunDto run = support.mapper().readValue(payloadJson, ApiDtos.PathRunDto.class);
            if (!pathRunId.equals(run.pathRunId())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "path run id mismatch for " + pathRunId);
            }
            if (run.schemaVersion() < PayloadSchemaGuard.MIN_SCHEMA_VERSION) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "path_run " + pathRunId + " lacks schemaVersion >= "
                                + PayloadSchemaGuard.MIN_SCHEMA_VERSION
                                + "; run V015 migration");
            }
            return run;
        } catch (SQLiteControlPlanePersistence.PersistenceException failure) {
            throw failure;
        } catch (JsonProcessingException | IllegalArgumentException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "persistent path run payload is invalid: " + pathRunId, failure);
        }
    }

    private void savePathTrace(Connection connection, SQLiteControlPlanePersistence.PathTraceData trace,
                               String createdAt) throws SQLException {
        PersistenceSupport.update(connection,
                "INSERT INTO path_traces(path_trace_id,path_run_id,scan_id,project_id,artifact_digest,task_id,"
                        + "experiment_plan_id,trace_plan_id,world_pack_id,posture_kind,exit_reason,legacy_incomplete,"
                        + "payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                trace.pathTraceId(), trace.pathRunId(), trace.scanId(), trace.projectId(),
                trace.artifactDigest(), trace.taskId(), trace.experimentPlanId(), trace.tracePlanId(),
                trace.worldPackId(), trace.postureKind(), trace.exitReason(), trace.legacyIncomplete() ? 1 : 0,
                trace.payloadJson(), createdAt);
    }
}
