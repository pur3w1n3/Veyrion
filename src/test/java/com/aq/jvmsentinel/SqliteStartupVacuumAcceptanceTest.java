package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * 启动时按 freelist 阈值 VACUUM：有空闲页则回收，失败不阻断（本测覆盖成功回收路径）。
 */
public final class SqliteStartupVacuumAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-startup-vacuum");
        Path database = root.resolve("control-plane.db");

        new SQLiteControlPlanePersistence(database, root);

        long freelistBefore;
        long sizeBefore;
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.executeUpdate("CREATE TABLE vacuum_pad(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)");
            byte[] payload = new byte[8_192];
            try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO vacuum_pad(payload) VALUES(?)")) {
                insert.setBytes(1, payload);
                for (int i = 0; i < 80; i++) {
                    insert.executeUpdate();
                }
            }
            statement.executeUpdate("DROP TABLE vacuum_pad");
            // WAL 下 freelist 可能仍挂在 wal；checkpoint 后主库 freelist 可见。
            statement.execute("PRAGMA wal_checkpoint(TRUNCATE)");
            freelistBefore = pragmaLong(statement, "freelist_count");
            sizeBefore = Files.size(database);
        }
        check(freelistBefore >= 1, "deleted pages must create freelist before startup vacuum");

        new SQLiteControlPlanePersistence(database, root);

        long freelistAfter;
        long sizeAfter;
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA wal_checkpoint(TRUNCATE)");
            freelistAfter = pragmaLong(statement, "freelist_count");
            sizeAfter = Files.size(database);
        }
        check(freelistAfter == 0, "startup vacuum should clear freelist_count");
        check(sizeAfter < sizeBefore, "startup vacuum should shrink database file");

        // 无显著 freelist 时再次打开不得失败（跳过 VACUUM）。
        new SQLiteControlPlanePersistence(database, root);

        System.out.println("SqliteStartupVacuumAcceptanceTest: PASS");
    }

    private static long pragmaLong(Statement statement, String name) throws Exception {
        try (ResultSet rows = statement.executeQuery("PRAGMA " + name)) {
            check(rows.next(), "PRAGMA " + name + " must return a row");
            return rows.getLong(1);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
