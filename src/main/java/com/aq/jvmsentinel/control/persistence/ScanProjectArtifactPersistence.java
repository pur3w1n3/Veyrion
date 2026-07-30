package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;

import java.nio.file.Path;
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
import java.util.Optional;

/**
 * 项目、制品、扫描及制品上传会话的持久化。
 */
final class ScanProjectArtifactPersistence {
    private final PersistenceSupport support;

    ScanProjectArtifactPersistence(PersistenceSupport support) {
        this.support = support;
    }

    SQLiteControlPlanePersistence.Snapshot load() {
        try (Connection connection = support.open()) {
            List<SQLiteControlPlanePersistence.ProjectData> projects = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT project_id,name,status,created_at,updated_at,deleted_at FROM projects ORDER BY created_at,project_id")) {
                while (rows.next()) {
                    projects.add(new SQLiteControlPlanePersistence.ProjectData(
                            rows.getString(1), rows.getString(2), rows.getString(3),
                            rows.getString(4), rows.getString(5), rows.getString(6)));
                }
            }

            List<SQLiteControlPlanePersistence.ArtifactData> artifacts = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT project_id,artifact_id,artifact_type,normalized_path,size_bytes,"
                                 + "artifact_digest,static_only,registered_at,original_file_name "
                                 + "FROM artifacts ORDER BY rowid")) {
                while (rows.next()) {
                    String originalFileName = rows.getString(9);
                    if (originalFileName == null || originalFileName.isBlank()) {
                        originalFileName = Path.of(rows.getString(4)).getFileName().toString();
                    }
                    ArtifactDescriptor descriptor = new ArtifactDescriptor(rows.getString(2),
                            ArtifactType.valueOf(rows.getString(3)), Path.of(rows.getString(4)),
                            rows.getLong(5), rows.getString(6), rows.getInt(7) != 0,
                            Instant.parse(rows.getString(8)), originalFileName);
                    artifacts.add(new SQLiteControlPlanePersistence.ArtifactData(rows.getString(1), descriptor));
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
                    ApiDtos.ScanDto dto = support.read(rows.getString(2), ApiDtos.ScanDto.class);
                    if (!scanId.equals(dto.scanId())) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "stored scan identifier does not match its payload");
                    }
                    scans.add(new ControlPlaneStore.ScanRecord(dto,
                            evidence.getOrDefault(scanId, Map.of()),
                            findings.getOrDefault(scanId, List.of()),
                            chains.getOrDefault(scanId, List.of())));
                }
            }
            // taint_graphs 保留在磁盘直至首次 staticFacts(scanId)；启动时不反序列化历史扫描的多 MB IR。
            Map<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> hypotheses =
                    loadHypotheses(connection);
            return new SQLiteControlPlanePersistence.Snapshot(projects, artifacts, scans, Map.of(), hypotheses);
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load Control Plane state", failure);
        }
    }

    void insertHypotheses(String scanId,
                            List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis> hypotheses,
                            String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(hypotheses, "hypotheses");
        support.transaction("could not persist security hypotheses", connection -> {
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM security_hypotheses WHERE scan_id=?")) {
                delete.setString(1, scanId);
                delete.executeUpdate(); // 首次持久化时 0 行属预期
            }
            for (com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis item : hypotheses) {
                if (item == null) {
                    continue;
                }
                if (!scanId.equals(item.scanId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "hypothesis scanId does not match insert scan");
                }
                PersistenceSupport.update(connection,
                        "INSERT INTO security_hypotheses(hypothesis_id,scan_id,payload_json) VALUES(?,?,?)",
                        item.hypothesisId(), scanId, support.write(item.toMap()));
            }
            String projectId;
            try (PreparedStatement lookup = connection.prepareStatement(
                    "SELECT project_id FROM scans WHERE scan_id=?")) {
                lookup.setString(1, scanId);
                try (ResultSet rows = lookup.executeQuery()) {
                    if (!rows.next()) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "scan not found for security hypotheses: " + scanId);
                    }
                    projectId = rows.getString(1);
                }
            }
            PersistenceSupport.audit(connection, projectId, actorId, "scan.security_hypotheses", "scan", scanId,
                    "{\"count\":" + hypotheses.size() + "}", Instant.now().toString());
        });
    }

    /** 惰性加载单个扫描的 static facts IR；供 ControlPlaneStore.staticFacts 使用。 */
    Optional<StaticFactSnapshot> loadTaintGraph(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return Optional.empty();
        }
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT graph_json FROM taint_graphs WHERE scan_id=?")) {
            statement.setString(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                return Optional.of(StaticFactSnapshot.fromJson(rows.getString(1)));
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not load static facts for scan", failure);
        }
    }

    void insertTaintGraph(String scanId, String graphJson, String createdAt, String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(graphJson, "graphJson");
        Objects.requireNonNull(createdAt, "createdAt");
        support.transaction("could not persist static facts", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT OR REPLACE INTO taint_graphs(scan_id, graph_json, created_at) VALUES(?,?,?)",
                    scanId, graphJson, createdAt);
            String projectId;
            try (PreparedStatement lookup = connection.prepareStatement(
                    "SELECT project_id FROM scans WHERE scan_id=?")) {
                lookup.setString(1, scanId);
                try (ResultSet rows = lookup.executeQuery()) {
                    if (!rows.next()) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "scan not found for static facts: " + scanId);
                    }
                    projectId = rows.getString(1);
                }
            }
            PersistenceSupport.audit(connection, projectId, actorId, "scan.static_facts", "scan", scanId,
                    "{\"coverage\":\"persisted\"}", createdAt);
        });
    }

    void insertProject(String id, String name, String status, String createdAt, String updatedAt,
                       String actorId) {
        support.transaction("could not create project", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO projects(project_id,name,status,created_at,updated_at) VALUES(?,?,?,?,?)",
                    id, name, status, createdAt, updatedAt);
            PersistenceSupport.audit(connection, id, actorId, "project.create", "project", id, "{}", createdAt);
        });
    }

    void updateProject(String id, String name, String status, String updatedAt, String actorId) {
        support.transaction("could not update project", connection -> {
            PersistenceSupport.update(connection,
                    "UPDATE projects SET name=?,status=?,updated_at=? WHERE project_id=? AND deleted_at IS NULL",
                    name, status, updatedAt, id);
            PersistenceSupport.audit(connection, id, actorId, "project.update", "project", id,
                    "{\"status\":\"" + status + "\"}", updatedAt);
        });
    }

    void softDeleteProject(String id, String deletedAt, String actorId) {
        support.transaction("could not delete project", connection -> {
            PersistenceSupport.audit(connection, id, actorId, "project.delete", "project", id, "{}", deletedAt);
            PersistenceSupport.update(connection,
                    "UPDATE projects SET status='DELETED',updated_at=?,deleted_at=? "
                            + "WHERE project_id=? AND deleted_at IS NULL",
                    deletedAt, deletedAt, id);
        });
    }

    void insertArtifact(String projectId, ArtifactDescriptor descriptor, String actorId) {
        support.transaction("could not register artifact", connection -> {
            PersistenceSupport.update(connection,
                    "INSERT INTO artifacts(project_id,artifact_digest,artifact_id,artifact_type,"
                            + "normalized_path,size_bytes,static_only,registered_at,original_file_name) "
                            + "VALUES(?,?,?,?,?,?,?,?,?) "
                            + "ON CONFLICT(project_id,artifact_digest) DO UPDATE SET artifact_id=excluded.artifact_id,"
                            + "artifact_type=excluded.artifact_type,normalized_path=excluded.normalized_path,"
                            + "size_bytes=excluded.size_bytes,static_only=excluded.static_only,"
                            + "registered_at=excluded.registered_at,"
                            + "original_file_name=COALESCE(excluded.original_file_name,artifacts.original_file_name)",
                    projectId, descriptor.sha256(), descriptor.artifactId(), descriptor.type().name(),
                    descriptor.normalizedPath().toString(), descriptor.sizeBytes(), descriptor.staticOnly() ? 1 : 0,
                    descriptor.registeredAt().toString(), descriptor.originalFileName());
            PersistenceSupport.audit(connection, projectId, actorId, "artifact.register", "artifact",
                    descriptor.artifactId(), "{\"digest\":\"" + descriptor.sha256() + "\"}",
                    descriptor.registeredAt().toString());
        });
    }

    void insertScan(ControlPlaneStore.ScanRecord record, String actorId) {
        Objects.requireNonNull(record, "record");
        try (Connection connection = support.open()) {
            connection.setAutoCommit(false);
            try {
                ApiDtos.ScanDto dto = record.dto();
                PersistenceSupport.update(connection,
                        "INSERT INTO scans(scan_id,project_id,artifact_digest,payload_json,created_at)"
                                + " VALUES(?,?,?,?,?)",
                        dto.scanId(), dto.projectId(), dto.artifactDigest(), support.write(dto), dto.createdAt());
                for (ApiDtos.EvidenceDto item : record.evidence().values()) {
                    PersistenceSupport.update(connection,
                            "INSERT INTO evidence(evidence_id,scan_id,project_id,payload_json) VALUES(?,?,?,?)",
                            item.evidenceId(), dto.scanId(), dto.projectId(), support.write(item));
                }
                for (ApiDtos.FindingDto item : record.findings()) {
                    PersistenceSupport.update(connection,
                            "INSERT INTO findings(finding_id,scan_id,project_id,payload_json,root_cause_json)"
                                    + " VALUES(?,?,?,?,?)",
                            item.findingId(), dto.scanId(), dto.projectId(), support.write(item),
                            support.rootCauseColumnJson(item));
                }
                for (ApiDtos.AttackChainDto item : record.chains()) {
                    PersistenceSupport.update(connection,
                            "INSERT INTO attack_chains(chain_id,scan_id,project_id,payload_json) VALUES(?,?,?,?)",
                            item.chainId(), dto.scanId(), dto.projectId(), support.write(item));
                }
                PersistenceSupport.audit(connection, dto.projectId(), actorId, "scan.run", "scan", dto.scanId(),
                        "{\"verificationStatus\":\"" + dto.verificationStatus() + "\"}", dto.createdAt());
                connection.commit();
            } catch (Exception failure) {
                PersistenceSupport.rollback(connection, failure);
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not persist scan", failure);
        }
    }

    /**
     * 硬删除单个扫描及其 scan 作用域依赖项。无 ON DELETE CASCADE 的子表须显式先删，
     * 以保证 FK 检查 fail-closed 且不残留 worker lease。
     */
    void deleteScan(ControlPlaneStore.ScanRecord record, String actorId, String now) {
        Objects.requireNonNull(record, "record");
        ApiDtos.ScanDto dto = record.dto();
        String scanId = dto.scanId();
        String projectId = dto.projectId();
        support.transaction("could not delete scan", connection -> {
            try (PreparedStatement active = connection.prepareStatement(
                    "SELECT COUNT(*) FROM worker_tasks WHERE scan_id=? AND project_id=? "
                            + "AND lifecycle IN ('QUEUED','LEASED','RUNNING','PAUSED')")) {
                active.setString(1, scanId);
                active.setString(2, projectId);
                try (ResultSet rows = active.executeQuery()) {
                    if (rows.next() && rows.getInt(1) > 0) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "active worker task must be cancelled before scan deletion");
                    }
                }
            }
            try (PreparedStatement activeJobs = connection.prepareStatement(
                    "SELECT COUNT(*) FROM ai_jobs WHERE scan_id=? AND project_id=? "
                            + "AND status IN ('QUEUED','RUNNING')")) {
                activeJobs.setString(1, scanId);
                activeJobs.setString(2, projectId);
                try (ResultSet rows = activeJobs.executeQuery()) {
                    if (rows.next() && rows.getInt(1) > 0) {
                        throw new SQLiteControlPlanePersistence.PersistenceException(
                                "active AI job must be cancelled before scan deletion");
                    }
                }
            }
            // 子表对给定 scan 常为空。update() 要求恰好一行；子 DELETE 用 deleteMatching 允许 0 行。
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM worker_trace_chunks WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM worker_tasks WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM dynamic_probe_plans WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM path_runs WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM path_traces WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM experiment_plans WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM trace_plans WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM world_packs WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM contrast_ledger_snapshots WHERE scan_id=?", scanId);
            PersistenceSupport.deleteMatching(connection, "DELETE FROM taint_graphs WHERE scan_id=?", scanId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM security_hypotheses WHERE scan_id=?", scanId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM verified_findings WHERE scan_id=?", scanId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM audit_pipeline_runs WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection, "DELETE FROM sse_events WHERE scan_id=?", scanId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM evidence WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM findings WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM attack_chains WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.deleteMatching(connection,
                    "DELETE FROM ai_jobs WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.update(connection, "DELETE FROM scans WHERE scan_id=? AND project_id=?",
                    scanId, projectId);
            PersistenceSupport.audit(connection, projectId, actorId, "scan.delete", "scan", scanId, "{}", now);
        });
    }

    List<ArtifactUploadService.PersistedSession> loadArtifactUploads() {
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT upload_id,project_id,file_name,size_bytes,sha256,next_offset,created_at,expires_at "
                             + "FROM artifact_upload_sessions ORDER BY upload_id");
             ResultSet rows = statement.executeQuery()) {
            List<ArtifactUploadService.PersistedSession> result = new ArrayList<>();
            while (rows.next()) {
                result.add(new ArtifactUploadService.PersistedSession(
                        rows.getString(1), rows.getString(2), rows.getString(3), rows.getLong(4),
                        rows.getString(5), rows.getLong(6), Instant.parse(rows.getString(7)),
                        Instant.parse(rows.getString(8))));
            }
            if (result.size() > 256) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "persistent upload session limit exceeded");
            }
            return List.copyOf(result);
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof SQLiteControlPlanePersistence.PersistenceException persistenceFailure) {
                throw persistenceFailure;
            }
            throw PersistenceSupport.databaseFailure("could not load persistent artifact uploads",
                    failure instanceof SQLException sql ? sql : new SQLException(failure));
        }
    }

    void persistArtifactUpload(ArtifactUploadService.PersistedSession session) {
        Objects.requireNonNull(session, "session");
        support.transaction("could not persist artifact upload", connection -> PersistenceSupport.update(connection,
                "INSERT INTO artifact_upload_sessions(upload_id,project_id,file_name,size_bytes,sha256,next_offset,created_at,expires_at) "
                        + "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(upload_id) DO UPDATE SET project_id=excluded.project_id,"
                        + "file_name=excluded.file_name,size_bytes=excluded.size_bytes,sha256=excluded.sha256,"
                        + "next_offset=excluded.next_offset,created_at=excluded.created_at,expires_at=excluded.expires_at",
                session.uploadId(), session.projectId(), session.fileName(), session.sizeBytes(), session.sha256(),
                session.nextOffset(), session.createdAt().toString(), session.expiresAt().toString()));
    }

    void deleteArtifactUpload(String uploadId) {
        if (uploadId == null || uploadId.isBlank()) {
            return;
        }
        try (Connection connection = support.open();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM artifact_upload_sessions WHERE upload_id=?")) {
            statement.setString(1, uploadId);
            statement.executeUpdate();
        } catch (SQLException failure) {
            throw PersistenceSupport.databaseFailure("could not delete artifact upload", failure);
        }
    }

    private Map<String, Map<String, ApiDtos.EvidenceDto>> loadEvidence(Connection connection) throws SQLException {
        Map<String, Map<String, ApiDtos.EvidenceDto>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT evidence_id,scan_id,payload_json FROM evidence ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.EvidenceDto dto = support.read(rows.getString(3), ApiDtos.EvidenceDto.class);
                if (!rows.getString(1).equals(dto.evidenceId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "stored evidence identifier does not match its payload");
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
                ApiDtos.FindingDto dto = support.read(rows.getString(3), ApiDtos.FindingDto.class);
                if (!rows.getString(1).equals(dto.findingId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "stored finding identifier does not match its payload");
                }
                dto = support.mergeRootCauseColumn(dto, rows.getString(4));
                result.computeIfAbsent(rows.getString(2), ignored -> new ArrayList<>()).add(dto);
            }
        }
        return result;
    }

    private Map<String, List<ApiDtos.AttackChainDto>> loadChains(Connection connection) throws SQLException {
        Map<String, List<ApiDtos.AttackChainDto>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT chain_id,scan_id,payload_json FROM attack_chains ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.AttackChainDto dto = support.read(rows.getString(3), ApiDtos.AttackChainDto.class);
                if (!rows.getString(1).equals(dto.chainId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "stored attack-chain identifier does not match its payload");
                }
                result.computeIfAbsent(rows.getString(2), ignored -> new ArrayList<>()).add(dto);
            }
        }
        return result;
    }

    private Map<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> loadHypotheses(
            Connection connection) throws SQLException {
        Map<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> result = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT hypothesis_id,scan_id,payload_json FROM security_hypotheses ORDER BY rowid")) {
            while (rows.next()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> payload = support.read(rows.getString(3), Map.class);
                com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis hypothesis =
                        com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis.fromMap(payload);
                if (!rows.getString(1).equals(hypothesis.hypothesisId())
                        || !rows.getString(2).equals(hypothesis.scanId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "stored hypothesis identifier does not match its payload");
                }
                result.computeIfAbsent(rows.getString(2), ignored -> new ArrayList<>()).add(hypothesis);
            }
        } catch (SQLException missingTable) {
            if (missingTable.getMessage() != null
                    && missingTable.getMessage().toLowerCase(java.util.Locale.ROOT).contains("no such table")) {
                return result;
            }
            throw missingTable;
        }
        return result;
    }
}
