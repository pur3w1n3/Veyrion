package com.aq.jvmsentinel.control.persistence;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 控制面 SQLite schema 迁移：校验已应用版本并按序执行 DDL。
 */
final class MigrationSupport {
    static final List<String> MIGRATIONS = List.of(
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
            "db/migration/V020__verified_findings.sql",
            "db/migration/V021__artifact_original_file_name.sql",
            "db/migration/V022__pipeline_run_stage_attempt_identity.sql",
            "db/migration/V023__security_hypotheses.sql",
            "db/migration/V024__scope_security_hypothesis_ids.sql",
            "db/migration/V025__path_debug_contracts.sql",
            "db/migration/V026__probe_plan_payload.sql");
    static final int SCHEMA_VERSION = MIGRATIONS.size();

    private final PersistenceSupport support;

    MigrationSupport(PersistenceSupport support) {
        this.support = support;
    }

    void migrate() {
        List<String> sql = MIGRATIONS.stream().map(MigrationSupport::resource).toList();
        List<String> checksums = sql.stream().map(PersistenceSupport::sha256).toList();
        try (Connection connection = support.open()) {
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
                        throw new SQLiteControlPlanePersistence.MigrationException(
                                "unsupported or non-contiguous database schema version");
                    }
                    String expectedName = MIGRATIONS.get(version - 1);
                    String appliedName = rows.getString(2);
                    String expectedChecksum = checksums.get(version - 1);
                    String appliedChecksum = rows.getString(3);
                    if (!expectedName.equals(appliedName) || !expectedChecksum.equals(appliedChecksum)) {
                        throw new SQLiteControlPlanePersistence.MigrationException(
                                "database migration checksum mismatch for version " + version
                                        + " (" + expectedName + "); applied migrations must not be rewritten. "
                                        + "For local development, back up and recreate "
                                        + "<Artifacts>/.veyrion/control-plane.db after confirming no needed state");
                    }
                    current = version;
                }
            }
            if (current == SCHEMA_VERSION) {
                return;
            }
            for (int migration = current; migration < SCHEMA_VERSION; migration++) {
                // SQLite 在已开启事务内忽略 PRAGMA foreign_keys；须先关闭。
                try (Statement statement = connection.createStatement()) {
                    statement.execute("PRAGMA foreign_keys=OFF");
                    PersistenceSupport.requirePragma(statement, "foreign_keys", "0");
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
                            // 升级 fixture 保留表并重放后续迁移时，ADD COLUMN / CREATE INDEX 须幂等。
                            if (!isIdempotentSchemaReplayError(statementSql, alreadyApplied)) {
                                throw alreadyApplied;
                            }
                        }
                    }
                    PersistenceSupport.update(connection,
                            "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                            migration + 1, MIGRATIONS.get(migration), checksums.get(migration),
                            Instant.now().toString());
                    connection.commit();
                } catch (Exception failure) {
                    PersistenceSupport.rollback(connection, failure);
                    throw new SQLiteControlPlanePersistence.MigrationException("database migration failed", failure);
                } finally {
                    connection.setAutoCommit(true);
                    try (Statement statement = connection.createStatement()) {
                        statement.execute("PRAGMA foreign_keys=ON");
                        PersistenceSupport.requirePragma(statement, "foreign_keys", "1");
                    }
                }
            }
        } catch (SQLException failure) {
            throw new SQLiteControlPlanePersistence.MigrationException("database migration failed", failure);
        }
    }

    /** 去除行注释后按分号拆分迁移 SQL（避免 `-- ...; ...` 破坏 DDL）。 */
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
        if (statementSql == null || failure == null) {
            return false;
        }
        String normalized = statementSql.replaceAll("\\s+", " ").trim().toUpperCase(Locale.ROOT);
        String message = failure.getMessage();
        if (message == null) {
            return false;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("ALTER TABLE") && normalized.contains("ADD COLUMN")
                && lower.contains("duplicate column name")) {
            return true;
        }
        return normalized.startsWith("CREATE INDEX") && lower.contains("already exists");
    }

    private static String resource(String name) {
        try (InputStream stream = SQLiteControlPlanePersistence.class.getClassLoader().getResourceAsStream(name)) {
            if (stream == null) {
                throw new SQLiteControlPlanePersistence.MigrationException("database migration resource is missing");
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException failure) {
            throw new SQLiteControlPlanePersistence.MigrationException(
                    "database migration resource could not be read", failure);
        }
    }
}
