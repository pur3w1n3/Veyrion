package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackManifest;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * P0-21: plan World Pack manifests for OBSERVE_FAIL and MOCK_CONTINUE dependency strategies.
 */
public final class WorldPackPlanner {
    public static final String PRODUCER = WorldPackManifest.PRODUCER;
    public static final String JDBC_STUB = "JDBC_STUB";
    public static final String REDIS_STUB = "REDIS_STUB";
    public static final String MYSQL_STUB = "MYSQL_STUB";

    private WorldPackPlanner() {
    }

    public static WorldPackManifest planMockContinue(String scanId) {
        String safeScan = normalizeScanId(scanId);
        return WorldPackManifest.minimalMockContinue("worldpack:mock:" + safeScan);
    }

    public static WorldPackManifest planObserveFail(String scanId, List<String> gaps) {
        String safeScan = normalizeScanId(scanId);
        List<String> normalizedGaps = normalizeGaps(gaps);
        return WorldPackManifest.observeFail("worldpack:observe:" + safeScan, normalizedGaps);
    }

    /**
     * Resolves the Docker JVM dependency mode for the <em>exploration</em> stage
     * (primary dynamic registration / cold start). Always {@link WorldPackDependencyMode#MOCK_CONTINUE}
     * so deny-all jars can bind HTTP under protocol-agnostic stubs before probes run.
     *
     * <p>Confirmation ({@link WorldPackDependencyMode#OBSERVE_FAIL}) is a separate stage —
     * use {@link #resolveRuntimeDependencyMode(Iterable, WorldPackExecutionStage)} with
     * {@link WorldPackExecutionStage#CONFIRMATION}. Never branch on MySQL/PostgreSQL/vendor.</p>
     */
    public static WorldPackDependencyMode resolveRuntimeDependencyMode(
            Iterable<PostureExperimentCompiler.CompiledPostureExperiment> plans) {
        return resolveRuntimeDependencyMode(plans, WorldPackExecutionStage.EXPLORATION);
    }

    /**
     * Stage-driven World Pack mode for one Docker JVM. Mode follows execution stage only;
     * posture mix and database vendor must not select the mode.
     *
     * @param plans reserved for future stage narrowing (ignored for mode selection today)
     */
    public static WorldPackDependencyMode resolveRuntimeDependencyMode(
            Iterable<PostureExperimentCompiler.CompiledPostureExperiment> plans,
            WorldPackExecutionStage stage) {
        Objects.requireNonNull(stage, "stage");
        return switch (stage) {
            case EXPLORATION -> WorldPackDependencyMode.MOCK_CONTINUE;
            case CONFIRMATION -> WorldPackDependencyMode.OBSERVE_FAIL;
        };
    }

    public static TraceExitReason classifyDependencyFailure(String message) {
        if (message == null || message.isBlank()) {
            return TraceExitReason.DEPENDENCY_UNAVAILABLE;
        }
        String upper = message.toUpperCase(Locale.ROOT);
        if (upper.contains("LICENSE") || upper.contains("MACHINE_CODE") || upper.contains("AUTHORIZATION_FILE")) {
            return TraceExitReason.LICENSE_UNAVAILABLE;
        }
        if (upper.contains("TABLE") && (upper.contains("NOT EXIST") || upper.contains("DOESN'T EXIST")
                || upper.contains("DOES NOT EXIST") || upper.contains("UNKNOWN TABLE")
                || upper.contains("NO SUCH TABLE") || upper.contains("MISSING TABLE"))) {
            return TraceExitReason.DEPENDENCY_DATA_GAP;
        }
        if (upper.contains("SCHEMA") || upper.contains("SEED") || upper.contains("COLUMN")
                || upper.contains("DATA_GAP") || upper.contains("EMPTY RESULT")) {
            return TraceExitReason.DEPENDENCY_DATA_GAP;
        }
        if (upper.contains("TENANT") || upper.contains("WORKFLOW") || upper.contains("UPLOAD_DIR")
                || upper.contains("BUSINESS_OBJECT") || upper.contains("WORLD_STATE")) {
            return TraceExitReason.WORLD_STATE_GAP;
        }
        if (upper.contains("CONNECTION REFUSED") || upper.contains("UNAVAILABLE")
                || upper.contains("TIMEOUT") || upper.contains("COMMUNICATIONS LINK FAILURE")
                || upper.contains("COULD NOT CONNECT")) {
            return TraceExitReason.DEPENDENCY_UNAVAILABLE;
        }
        return TraceExitReason.DEPENDENCY_UNAVAILABLE;
    }

    public static List<String> defaultMockStubs() {
        return List.of(JDBC_STUB, REDIS_STUB, MYSQL_STUB);
    }

    private static String normalizeScanId(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return "scan-unknown";
        }
        return scanId.trim();
    }

    private static List<String> normalizeGaps(List<String> gaps) {
        if (gaps == null || gaps.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String gap : gaps) {
            if (gap == null || gap.isBlank()) {
                continue;
            }
            String normalized = gap.trim().toUpperCase(Locale.ROOT);
            if (!normalized.equals("DEPENDENCY_UNAVAILABLE")
                    && !normalized.equals("DEPENDENCY_DATA_GAP")
                    && !normalized.equals("WORLD_STATE_GAP")
                    && !normalized.equals("LICENSE_UNAVAILABLE")) {
                out.add(normalized);
            } else {
                out.add(normalized);
            }
        }
        return List.copyOf(out);
    }

    public static WorldPackManifest migrateLegacyStubNames(WorldPackManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        List<String> stubs = new ArrayList<>();
        for (String stub : manifest.dependencyStubs()) {
            if (stub == null || stub.isBlank()) {
                continue;
            }
            stubs.add(migrateStubName(stub));
        }
        return new WorldPackManifest(
                manifest.schemaVersion(),
                manifest.worldPackId(),
                manifest.profileId(),
                manifest.dependencyMode(),
                manifest.env(),
                manifest.systemProperties(),
                manifest.licenseMaterials(),
                manifest.fileMaterials(),
                manifest.schemaSeeds(),
                stubs,
                manifest.missingMaterialGaps());
    }

    private static String migrateStubName(String stub) {
        String upper = stub.trim().toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "JDBC", "JDBC_MOCK", "DB_STUB" -> JDBC_STUB;
            case "REDIS", "REDIS_MOCK", "CACHE_STUB" -> REDIS_STUB;
            case "MYSQL", "MYSQL_MOCK", "SQL_STUB" -> MYSQL_STUB;
            default -> stub.trim();
        };
    }
}
