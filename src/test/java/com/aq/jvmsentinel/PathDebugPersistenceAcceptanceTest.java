package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/** V025 path-debug tables upgrade on empty DB. */
public final class PathDebugPersistenceAcceptanceTest {
    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        Path root = Files.createTempDirectory("veyrion-pathdebug-persist");
        Path database = root.resolve("state").resolve("control-plane.db");
        new SQLiteControlPlanePersistence(database, root);
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            for (String table : new String[]{"trace_plans", "world_packs", "path_traces"}) {
                try (ResultSet rows = statement.executeQuery(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='" + table + "'")) {
                    check(rows.next(), "V025 table exists: " + table);
                }
            }
        }
        System.out.println("PathDebugPersistenceAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}
