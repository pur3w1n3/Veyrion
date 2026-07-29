package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackManifest;
import com.aq.jvmsentinel.model.IdentityTrack;

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
        resolveRuntimeDependencyMode();
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

    private static void resolveRuntimeDependencyMode() {
        PostureExperimentCompiler.CompiledPostureExperiment coverage = stubPlan(
                "plan:coverage", RuntimePosture.coverage());
        PostureExperimentCompiler.CompiledPostureExperiment forced = stubPlan(
                "plan:forced", RuntimePosture.forced(List.of("GUARD:AUTH")));
        check(WorldPackPlanner.resolveRuntimeDependencyMode(List.of(coverage, forced))
                        == WorldPackDependencyMode.MOCK_CONTINUE,
                "exploration stage defaults MOCK_CONTINUE for mixed tracks");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(List.of(forced))
                        == WorldPackDependencyMode.MOCK_CONTINUE,
                "exploration stage forced-only still MOCK_CONTINUE");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(List.of())
                        == WorldPackDependencyMode.MOCK_CONTINUE,
                "empty plans keep exploration MOCK_CONTINUE");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(null)
                        == WorldPackDependencyMode.MOCK_CONTINUE,
                "null plans keep exploration MOCK_CONTINUE");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(
                                List.of(coverage, forced), WorldPackExecutionStage.EXPLORATION)
                        == WorldPackDependencyMode.MOCK_CONTINUE,
                "explicit EXPLORATION → MOCK_CONTINUE");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(
                                List.of(coverage, forced), WorldPackExecutionStage.CONFIRMATION)
                        == WorldPackDependencyMode.OBSERVE_FAIL,
                "CONFIRMATION stage → OBSERVE_FAIL (vendor-agnostic)");
        check(WorldPackPlanner.resolveRuntimeDependencyMode(
                                List.of(), WorldPackExecutionStage.CONFIRMATION)
                        == WorldPackDependencyMode.OBSERVE_FAIL,
                "CONFIRMATION ignores empty plans");
    }

    private static PostureExperimentCompiler.CompiledPostureExperiment stubPlan(
            String planId, RuntimePosture posture) {
        IdentityTrack track = posture.postureKind() == RuntimePostureKind.UNAUTH
                ? IdentityTrack.UNAUTH : IdentityTrack.ADMIN;
        return new PostureExperimentCompiler.CompiledPostureExperiment(
                planId,
                "traceplan:stub",
                posture.postureKind() == RuntimePostureKind.FORCED_REACHABILITY
                        ? "worldpack:mock:scan-wp" : "worldpack:observe:scan-wp",
                "entry:stub",
                "GET",
                "/stub",
                posture,
                track,
                List.of(),
                "",
                "",
                "empty-ok",
                List.of(),
                List.of(),
                "BUDGET");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
