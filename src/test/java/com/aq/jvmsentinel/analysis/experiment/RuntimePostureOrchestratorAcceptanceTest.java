package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-21: RuntimePostureOrchestrator acceptance.
 */
public final class RuntimePostureOrchestratorAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        defaultPostures();
        nonDockerForcedDenied();
        hostExecutionDenied();
        clientPolicyOverrideDenied();
        sanitizerForceDenied();
        coverageProvenance();
        System.out.println("RuntimePostureOrchestratorAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void defaultPostures() {
        List<RuntimePosture> postures = RuntimePostureOrchestrator.planDefaultPostures(
                List.of("GUARD:AUTH", "ROLE"), false);
        check(postures.stream().anyMatch(p -> p.postureKind() == RuntimePostureKind.UNAUTH),
                "default includes UNAUTH");
        check(postures.stream().anyMatch(p -> p.postureKind() == RuntimePostureKind.COVERAGE_POSTURE),
                "default includes COVERAGE_POSTURE");
        check(postures.stream().anyMatch(p -> p.postureKind() == RuntimePostureKind.FORCED_REACHABILITY),
                "default includes FORCED_REACHABILITY");
        check(postures.stream().noneMatch(p -> p.postureKind() == RuntimePostureKind.BYPASS),
                "BYPASS omitted without candidate");
    }

    private static void nonDockerForcedDenied() {
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(false, false, Map.of());
            check(false, "non-Docker forced must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("DOCKER_ONLY"), "non-Docker forced denied");
        }
    }

    private static void hostExecutionDenied() {
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, true, Map.of());
            check(false, "host execution must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("HOST_EXECUTION_DENIED"), "host execution denied");
        }
    }

    private static void clientPolicyOverrideDenied() {
        Map<String, Object> overrides = new LinkedHashMap<>();
        overrides.put("command", "rm -rf /");
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, overrides);
            check(false, "client command override must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("CLIENT_POLICY_OVERRIDE_DENIED"), "AI/frontend override denied");
        }
        overrides.clear();
        overrides.put("forcedGuardRefs", List.of("GUARD:AUTH"));
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, overrides);
            check(false, "client forcedGuardRefs must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("CLIENT_POLICY_OVERRIDE_DENIED"), "forcedGuardRefs override denied");
        }
    }

    private static void sanitizerForceDenied() {
        check(ForcedGuardKind.isForbiddenForceTarget("SANITIZER"), "sanitizer is forbidden target");
        Map<String, Object> overrides = new LinkedHashMap<>();
        overrides.put("serverGuardRefs", List.of("SANITIZER"));
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, overrides);
            check(false, "sanitizer force must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("FORBIDDEN_FORCE_TARGET"), "sanitizer force denied");
        }
        try {
            new RuntimePosture(RuntimePostureKind.FORCED_REACHABILITY,
                    RuntimePosture.PROVENANCE_INSTRUMENTATION,
                    List.of("SQL_PARAMETERIZATION"), true, "ADMIN");
            check(false, "sanitizer in posture record must throw");
        } catch (IllegalArgumentException expected) {
            check(true, "RuntimePosture rejects forbidden guard refs");
        }
    }

    private static void coverageProvenance() {
        RuntimePosture coverage = RuntimePostureOrchestrator.coveragePosture();
        check(RuntimePosture.PROVENANCE_SCAN_AUTH.equals(coverage.postureProvenance()),
                "coverage injects SCAN_AUTH_POSTURE provenance");
        RuntimePosture unauth = RuntimePostureOrchestrator.unauth();
        check(unauth.postureKind() == RuntimePostureKind.UNAUTH, "unauth for real wall");
        check("UNAUTH".equals(unauth.identityTrackWire()), "unauth track wire");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
