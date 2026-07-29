package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackManifest;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-21: WorldPackPlanner acceptance.
 */
public final class WorldPackPlannerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        mockContinuePlan();
        observeFailPlan();
        stubNameMigration();
        classifyDependencyFailure();
        System.out.println("WorldPackPlannerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void mockContinuePlan() {
        WorldPackManifest manifest = WorldPackPlanner.planMockContinue("scan-wp");
        check(manifest.dependencyMode() == WorldPackDependencyMode.MOCK_CONTINUE,
                "MOCK_CONTINUE mode");
        check(manifest.worldPackId().contains("scan-wp"), "worldPackId bound to scan");
        check(manifest.dependencyStubs().contains(WorldPackPlanner.JDBC_STUB), "JDBC_STUB present");
        check(manifest.dependencyStubs().contains(WorldPackPlanner.REDIS_STUB), "REDIS_STUB present");
        check(manifest.dependencyStubs().contains(WorldPackPlanner.MYSQL_STUB), "MYSQL_STUB present");
        check(manifest.missingMaterialGaps().isEmpty(), "mock continue has no gaps");
    }

    private static void observeFailPlan() {
        WorldPackManifest manifest = WorldPackPlanner.planObserveFail(
                "scan-wp",
                List.of("DEPENDENCY_UNAVAILABLE", "WORLD_STATE_GAP", "LICENSE_UNAVAILABLE"));
        check(manifest.dependencyMode() == WorldPackDependencyMode.OBSERVE_FAIL,
                "OBSERVE_FAIL mode");
        check(manifest.missingMaterialGaps().contains("DEPENDENCY_UNAVAILABLE"),
                "DEPENDENCY_UNAVAILABLE gap emitted");
        check(manifest.missingMaterialGaps().contains("WORLD_STATE_GAP"),
                "WORLD_STATE_GAP gap emitted");
        check(manifest.missingMaterialGaps().contains("LICENSE_UNAVAILABLE"),
                "LICENSE_UNAVAILABLE gap emitted");
    }

    private static void stubNameMigration() {
        WorldPackManifest legacy = new WorldPackManifest(
                WorldPackManifest.SCHEMA_VERSION,
                "worldpack:legacy",
                "default",
                WorldPackDependencyMode.MOCK_CONTINUE,
                java.util.Map.of(),
                java.util.Map.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of("JDBC", "REDIS_MOCK", "SQL_STUB"),
                List.of());
        WorldPackManifest migrated = WorldPackPlanner.migrateLegacyStubNames(legacy);
        check(migrated.dependencyStubs().contains(WorldPackPlanner.JDBC_STUB), "JDBC migrated");
        check(migrated.dependencyStubs().contains(WorldPackPlanner.REDIS_STUB), "REDIS migrated");
        check(migrated.dependencyStubs().contains(WorldPackPlanner.MYSQL_STUB), "MYSQL migrated");
    }

    private static void classifyDependencyFailure() {
        check(WorldPackPlanner.classifyDependencyFailure("Connection refused to mysql:3306")
                        == TraceExitReason.DEPENDENCY_UNAVAILABLE,
                "connection refused → DEPENDENCY_UNAVAILABLE");
        check(WorldPackPlanner.classifyDependencyFailure("Table 'users' doesn't exist")
                        == TraceExitReason.DEPENDENCY_DATA_GAP,
                "missing table → DEPENDENCY_DATA_GAP");
        check(WorldPackPlanner.classifyDependencyFailure("LICENSE file missing")
                        == TraceExitReason.LICENSE_UNAVAILABLE,
                "license missing → LICENSE_UNAVAILABLE");
        check(WorldPackPlanner.classifyDependencyFailure("tenant context unavailable")
                        == TraceExitReason.WORLD_STATE_GAP,
                "tenant gap → WORLD_STATE_GAP");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
