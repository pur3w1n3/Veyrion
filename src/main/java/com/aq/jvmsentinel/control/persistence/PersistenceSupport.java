package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.control.ApiDtos;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
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
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SQLite 连接、事务与 JSON 编解码的共享基础设施。
 */
final class PersistenceSupport {
    static final int BUSY_TIMEOUT_MILLIS = 5_000;
    /** 启动时仅当 freelist 页数达到该阈值才 VACUUM，避免空库每次空转。 */
    static final long STARTUP_VACUUM_FREELIST_THRESHOLD = 1L;

    private static final Logger LOG = Logger.getLogger(PersistenceSupport.class.getName());

    private final Path databasePath;
    private final String jdbcUrl;
    private final ObjectMapper mapper = new ObjectMapper();

    PersistenceSupport(Path databasePath) {
        this.databasePath = databasePath;
        this.jdbcUrl = "jdbc:sqlite:" + databasePath;
    }

    Path databasePath() {
        return databasePath;
    }

    ObjectMapper mapper() {
        return mapper;
    }

    Connection open() throws SQLException {
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
            if (!configured) {
                connection.close();
            }
        }
    }

    /**
     * 控制面启动独占窗口：仅当 freelist 显著时执行一次 {@code VACUUM}，回收删除扫描后的空闲页。
     * 失败只记警告，不阻断启动；勿在 scan delete 热路径调用。
     */
    void vacuumOnStartupIfNeeded() {
        long startedAt = System.nanoTime();
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            long freelistCount = pragmaLong(statement, "freelist_count");
            long pageCount = pragmaLong(statement, "page_count");
            if (freelistCount < STARTUP_VACUUM_FREELIST_THRESHOLD) {
                LOG.info(() -> "Control Plane SQLite VACUUM skipped (freelist_count="
                        + freelistCount + ", page_count=" + pageCount
                        + ", threshold=" + STARTUP_VACUUM_FREELIST_THRESHOLD + ")");
                return;
            }
            System.out.println("Control Plane SQLite VACUUM starting (freelist_count="
                    + freelistCount + ", page_count=" + pageCount + ", db="
                    + databasePath.toAbsolutePath().normalize() + ")");
            statement.execute("VACUUM");
            long elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L;
            long freelistAfter = pragmaLong(statement, "freelist_count");
            long pageCountAfter = pragmaLong(statement, "page_count");
            System.out.println("Control Plane SQLite VACUUM finished in " + elapsedMs
                    + "ms (freelist_count=" + freelistAfter + ", page_count=" + pageCountAfter + ")");
        } catch (Exception failure) {
            long elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L;
            String detail = failure.getMessage() == null ? failure.getClass().getSimpleName()
                    : failure.getMessage();
            System.err.println("Control Plane SQLite VACUUM failed after " + elapsedMs
                    + "ms (continuing startup): " + detail);
            LOG.log(Level.WARNING, "Control Plane SQLite VACUUM failed; startup continues", failure);
        }
    }

    private static long pragmaLong(Statement statement, String name) throws SQLException {
        try (ResultSet result = statement.executeQuery("PRAGMA " + name)) {
            if (!result.next()) {
                throw new SQLException("PRAGMA " + name + " returned no rows");
            }
            return result.getLong(1);
        }
    }

    void transaction(String message, SqlWork work) {
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

    static void update(Connection connection, String sql, Object... values) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < values.length; i++) {
                statement.setObject(i + 1, values[i]);
            }
            int changed = statement.executeUpdate();
            if (changed != 1) {
                throw new SQLException("persistence update affected " + changed + " rows");
            }
        }
    }

    /** 可能匹配零行或多行的 DELETE/UPDATE（级联扫描清理）。 */
    static void deleteMatching(Connection connection, String sql, Object... values) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < values.length; i++) {
                statement.setObject(i + 1, values[i]);
            }
            statement.executeUpdate();
        }
    }

    static void audit(Connection connection, String projectId, String operatorId, String action,
                      String targetType, String targetId, String details, String now) throws SQLException {
        update(connection, "INSERT INTO audit_events(audit_event_id,project_id,operator_id,action,target_type,"
                        + "target_id,outcome,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                "audit-" + UUID.randomUUID(), projectId, operatorId, action, targetType, targetId,
                "SUCCESS", details, now);
    }

    String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "could not encode persistent snapshot", failure);
        }
    }

    <T> T read(String value, Class<T> type) {
        try {
            return mapper.readValue(value, type);
        } catch (JsonProcessingException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "persistent snapshot is invalid", failure);
        }
    }

    String rootCauseColumnJson(ApiDtos.FindingDto item) {
        if (item == null || item.rootCause() == null || item.rootCause().isEmpty()) {
            return null;
        }
        return write(item.rootCause());
    }

    ApiDtos.FindingDto mergeRootCauseColumn(ApiDtos.FindingDto dto, String rootCauseJson) {
        if (dto == null) {
            return null;
        }
        if (dto.rootCause() != null && !dto.rootCause().isEmpty()) {
            return dto;
        }
        if (rootCauseJson == null || rootCauseJson.isBlank()) {
            return dto;
        }
        try {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> parsed = mapper.readValue(rootCauseJson, java.util.Map.class);
            if (parsed == null || parsed.isEmpty()) {
                return dto;
            }
            return dto.withRootCause(parsed);
        } catch (JsonProcessingException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "stored finding root_cause_json is invalid", failure);
        }
    }

    String extractFuzzStrategyJson(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) {
            return null;
        }
        try {
            var root = mapper.readTree(payloadJson);
            var node = root.get("fuzzStrategyJson");
            if (node == null || node.isNull()) {
                node = root.get("fuzzStrategy");
            }
            if (node == null || node.isNull() || !node.isTextual()) {
                return null;
            }
            String text = node.asText();
            return text == null || text.isBlank() ? null : text;
        } catch (JsonProcessingException ignored) {
            return null;
        }
    }

    static Path controlledDatabasePath(Path requested, Path allowedRoot) {
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
            if (parent == null) {
                throw new IllegalArgumentException("database path requires a parent directory");
            }
            Files.createDirectories(parent);
            Path realParent = parent.toRealPath();
            if (!realParent.startsWith(root)) {
                throw new IllegalArgumentException("database parent resolves outside allowedRoot");
            }
            Path result = realParent.resolve(normalized.getFileName()).normalize();
            if (Files.exists(result, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(result)) {
                throw new IllegalArgumentException("database path must not be a symbolic link");
            }
            if (Files.exists(result, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(result, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("database path must be a regular file");
            }
            return result;
        } catch (IOException failure) {
            throw new IllegalArgumentException("database path could not be secured", failure);
        }
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    static SQLiteControlPlanePersistence.PersistenceException databaseFailure(
            String message, SQLException failure) {
        return new SQLiteControlPlanePersistence.PersistenceException(message, failure);
    }

    /** SQLITE_BUSY (5) / SQLITE_LOCKED (6) 及驱动层 "database is locked" 消息。 */
    static boolean isSqliteBusyOrLocked(Throwable failure) {
        for (Throwable cursor = failure; cursor != null; cursor = cursor.getCause()) {
            if (cursor instanceof SQLException sql) {
                int code = sql.getErrorCode();
                if (code == 5 || code == 6) {
                    return true;
                }
                String message = sql.getMessage();
                if (message != null) {
                    String lower = message.toLowerCase(Locale.ROOT);
                    if (lower.contains("sqlite_busy")
                            || lower.contains("sqlite_locked")
                            || lower.contains("database is locked")
                            || lower.contains("database table is locked")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    static void sleepQuietly(long millis) {
        try {
            Thread.sleep(Math.max(1L, millis));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    static void requirePragma(Statement statement, String name, String expected) throws SQLException {
        try (java.sql.ResultSet result = statement.executeQuery("PRAGMA " + name)) {
            if (!result.next() || !expected.equals(result.getString(1))) {
                throw new SQLException("required SQLite PRAGMA was not applied: " + name);
            }
        }
    }

    @FunctionalInterface
    interface SqlWork {
        void run(Connection connection) throws SQLException;
    }
}
