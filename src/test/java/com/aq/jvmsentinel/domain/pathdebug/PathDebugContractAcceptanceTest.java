package com.aq.jvmsentinel.domain.pathdebug;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 说明：P0-21：path-debug domain contract 往返与 legacy 兼容。
 */
public final class PathDebugContractAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        tracePlanRoundTrip();
        pathTraceRoundTrip();
        worldPackRoundTrip();
        runtimePostureRoundTrip();
        legacyPathRunWithoutPosture();
        neverInventForcedFromLegacy();
        System.out.println("PathDebugContractAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void tracePlanRoundTrip() {
        TracePlan plan = new TracePlan(
                TracePlan.SCHEMA_VERSION,
                "traceplan:entry-1",
                "entry-1",
                "GET",
                "/api/ping",
                "demo.PingController",
                List.of(new TracePlan.ParameterSpec("", "QUERY", "EMPTY_INPUT", true, "empty legal")),
                List.of("Controller#ping"),
                List.of("EFFECT:LOG"),
                List.of("GUARD:AUTH"),
                List.of("REFLECTION:handler"),
                "empty-input rationale",
                64,
                256,
                15_000);
        Map<String, Object> wire = plan.toMap();
        TracePlan restored = TracePlan.fromMap(wire);
        check(restored.tracePlanId().equals(plan.tracePlanId()), "TracePlan id round-trip");
        check(restored.expectedEffectRefs().equals(plan.expectedEffectRefs()), "TracePlan effects round-trip");
        check(!restored.emptyInputRationale().isBlank(), "TracePlan empty rationale preserved");
    }

    private static void pathTraceRoundTrip() {
        RuntimePosture posture = RuntimePosture.unauth();
        PathTrace trace = new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace:1",
                "pathrun:1",
                "probe:1",
                "plan:1",
                "traceplan:1",
                "entry-1",
                "UNAUTH",
                posture,
                "worldpack:1",
                "corr-1",
                1,
                List.of(new TraceEvent(0, TraceEventKind.ENTRY_HIT, "GET /x", "entry-1", "", false, Map.of(), "")),
                List.of(),
                TraceExitReason.AUTH_CHALLENGE,
                "Controller#x",
                List.of(),
                false);
        PathTrace restored = PathTrace.fromMap(trace.toMap());
        check(restored.pathTraceId().equals(trace.pathTraceId()), "PathTrace id round-trip");
        check(restored.posture().postureKind() == RuntimePostureKind.UNAUTH, "PathTrace posture round-trip");
        check(restored.exitReason() == TraceExitReason.AUTH_CHALLENGE, "PathTrace exit round-trip");
    }

    private static void worldPackRoundTrip() {
        WorldPackManifest manifest = WorldPackManifest.minimalMockContinue("worldpack:mock:scan-1");
        WorldPackManifest restored = WorldPackManifest.fromMap(manifest.toMap());
        check(restored.worldPackId().equals(manifest.worldPackId()), "WorldPack id round-trip");
        check(restored.dependencyMode() == WorldPackDependencyMode.MOCK_CONTINUE, "WorldPack mode round-trip");
        check(restored.dependencyStubs().contains("JDBC_STUB"), "WorldPack JDBC_STUB present");
    }

    private static void runtimePostureRoundTrip() {
        RuntimePosture posture = RuntimePosture.coverage();
        RuntimePosture restored = RuntimePosture.fromMap(posture.toMap());
        check(restored.postureKind() == RuntimePostureKind.COVERAGE_POSTURE, "posture kind round-trip");
        check(RuntimePosture.PROVENANCE_SCAN_AUTH.equals(restored.postureProvenance()),
                "coverage provenance round-trip");
        check("ADMIN".equals(restored.identityTrackWire()), "identity track wire round-trip");
    }

    private static void legacyPathRunWithoutPosture() {
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("pathRunId", "pathrun:legacy-1");
        legacy.put("entryRef", "entry:legacy");
        legacy.put("track", "UNAUTH");
        legacy.put("httpStatus", 200);
        PathRunPathDebugView view = PathRunPathDebugView.fromPathRunWire(legacy);
        check(view.legacyIncomplete(), "old PathRun without posture → legacy incomplete");
        check(TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE.name().equals(view.exitReason()),
                "legacy exit reason stamped");
    }

    private static void neverInventForcedFromLegacy() {
        Map<String, Object> legacyPosture = new LinkedHashMap<>();
        legacyPosture.put("postureKind", "FORCED_REACHABILITY");
        legacyPosture.put("postureProvenance", RuntimePosture.PROVENANCE_LEGACY);
        legacyPosture.put("forcedGuardRefs", List.of("GUARD:AUTH"));
        RuntimePosture restored = RuntimePosture.fromMap(legacyPosture);
        check(restored.postureKind() == RuntimePostureKind.UNAUTH,
                "never invent FORCED_REACHABILITY from legacy");
        check(RuntimePosture.PROVENANCE_LEGACY.equals(restored.postureProvenance()),
                "legacy provenance preserved");
        check(restored.forcedGuardRefs().isEmpty(), "legacy forced guard refs cleared");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
