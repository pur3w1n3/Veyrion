package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.security.ProviderSecretCipher.EncryptedSecret;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretScope;
import com.aq.jvmsentinel.security.auth.OperatorRole;
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
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Plain-JDBC SQLite persistence for immutable Control Plane snapshots.
 *
 * <p>Only artifact metadata and its controlled host path are stored. Artifact
 * bytes remain in the content source selected by {@code ArtifactRegistry}.</p>
 */
public final class SQLiteControlPlanePersistence {
    private static final int BUSY_TIMEOUT_MILLIS = 5_000;
    private static final List<String> MIGRATIONS = List.of(
            "db/migration/V001__control_plane.sql",
            "db/migration/V002__management_configuration.sql");
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
                    update(connection, "INSERT INTO findings(finding_id,scan_id,project_id,payload_json) VALUES(?,?,?,?)",
                            item.findingId(), dto.scanId(), dto.projectId(), write(item));
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
                     "SELECT project_id,role,provider_id,model,updated_at"
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
                            + "model,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(project_id,role) DO UPDATE SET "
                            + "provider_id=excluded.provider_id,model=excluded.model,updated_at=excluded.updated_at",
                    binding.projectId(), binding.role().name(), LOCAL_WORKSPACE, binding.providerId(),
                    binding.model(), binding.updatedAt());
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
            update(connection, "INSERT INTO ai_jobs(ai_job_id,project_id,role,status,error_code,stages_json,"
                            + "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)"
                            + " ON CONFLICT(ai_job_id) DO UPDATE SET status=excluded.status,"
                            + "error_code=excluded.error_code,stages_json=excluded.stages_json,"
                            + "updated_at=excluded.updated_at",
                    job.aiJobId(), job.projectId(), job.role().name(), job.status(), job.errorCode(),
                    job.stagesJson(), job.createdAt(), job.updatedAt());
            audit(connection, job.projectId(), actorId, action, "ai-job", job.aiJobId(),
                    "{\"status\":\"" + job.status() + "\"}", job.updatedAt());
        });
    }

    public List<AiJobData> listAiJobs(String projectId) {
        String sql = "SELECT ai_job_id,project_id,role,status,error_code,stages_json,created_at,updated_at"
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
             ResultSet rows = statement.executeQuery("SELECT finding_id,scan_id,payload_json FROM findings ORDER BY rowid")) {
            while (rows.next()) {
                ApiDtos.FindingDto dto = read(rows.getString(3), ApiDtos.FindingDto.class);
                if (!rows.getString(1).equals(dto.findingId())) {
                    throw new PersistenceException("stored finding identifier does not match its payload");
                }
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
                    if (!MIGRATIONS.get(version - 1).equals(rows.getString(2))
                            || !checksums.get(version - 1).equals(rows.getString(3))) {
                        throw new MigrationException("database migration checksum mismatch");
                    }
                    current = version;
                }
            }
            if (current == SCHEMA_VERSION) return;
            for (int migration = current; migration < SCHEMA_VERSION; migration++) {
                connection.setAutoCommit(false);
                try {
                    for (String statementSql : sql.get(migration).split(";")) {
                        if (!statementSql.isBlank()) {
                            try (Statement statement = connection.createStatement()) {
                                statement.execute(statementSql);
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
                rows.getString(3), rows.getString(4), rows.getString(5));
    }

    private static AiJobData job(ResultSet rows) throws SQLException {
        return new AiJobData(rows.getString(1), rows.getString(2), AgentRole.valueOf(rows.getString(3)),
                rows.getString(4), rows.getString(5), rows.getString(6), rows.getString(7), rows.getString(8));
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
    public record OperatorData(String operatorId, String username, OperatorRole role,
                               String createdAt, String updatedAt) { }
    public record ProviderData(String providerId, String name, ProviderKind kind, String baseUrl,
                               String model, boolean enabled, String createdAt, String updatedAt,
                               boolean hasCredential) { }
    public record StoredSecret(SecretScope scope, EncryptedSecret encrypted) { }
    public record RoleBindingData(String projectId, AgentRole role, String providerId,
                                  String model, String updatedAt) { }
    public record AiJobData(String aiJobId, String projectId, AgentRole role, String status,
                            String errorCode, String stagesJson, String createdAt, String updatedAt) { }
    public record AuditData(String auditEventId, String projectId, String operatorId, String action,
                            String targetType, String targetId, String outcome, String detailsJson,
                            String createdAt) { }
    public record Snapshot(List<ProjectData> projects, List<ArtifactData> artifacts,
                           List<ControlPlaneStore.ScanRecord> scans) {
        public Snapshot {
            projects = List.copyOf(projects);
            artifacts = List.copyOf(artifacts);
            scans = List.copyOf(scans);
        }
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
