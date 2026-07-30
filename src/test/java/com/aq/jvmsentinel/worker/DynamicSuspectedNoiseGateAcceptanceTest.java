package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.PathOutcomeClass;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-15 / P0-20 回归：httpStatus=-1 / UNKNOWN / MOCK-gap 不得变为 DYNAMIC_SUSPECTED。
 * 建模 scan-7b619e8a65064fa9 洪泛失败模式，不携带私有制品数据。
 */
public final class DynamicSuspectedNoiseGateAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        negativeStatusAlwaysUnreached();
        unknownAndTimeoutUnreached();
        dependencyMockGapUnreached();
        reachedNoBindUnreached();
        observedHttpMaySuspect();
        floodRatioGate();
        startupDiagnosticsClassify();
        System.out.println("DynamicSuspectedNoiseGateAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void negativeStatusAlwaysUnreached() {
        for (PathOutcomeClass outcome : PathOutcomeClass.values()) {
            String status = TraceProjectionService.verificationStatusFor(outcome, -1);
            check(ApiDtos.UNREACHED.equals(status),
                    "httpStatus=-1 must be UNREACHED for " + outcome);
        }
    }

    private static void unknownAndTimeoutUnreached() {
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.UNKNOWN, 200)),
                "UNKNOWN outcome is UNREACHED even with status text");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.BUSINESS_TIMEOUT, 504)),
                "BUSINESS_TIMEOUT is UNREACHED");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.TRANSPORT_ERROR, 0)),
                "TRANSPORT_ERROR is UNREACHED");
    }

    private static void dependencyMockGapUnreached() {
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.DEPENDENCY_MOCK_GAP, -1, null, true)),
                "MOCK dependency gap never DYNAMIC_SUSPECTED");
    }

    private static void reachedNoBindUnreached() {
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.REACHED_NO_BIND, 404, false, false)),
                "404 REACHED_NO_BIND is diagnostic UNREACHED, not suspected vuln");
    }

    private static void observedHttpMaySuspect() {
        check(ApiDtos.DYNAMIC_SUSPECTED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.HTTP_OBSERVED, 302, true, false)),
                "entryHit HTTP observation may be DYNAMIC_SUSPECTED");
        check(ApiDtos.DYNAMIC_SUSPECTED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.HTTP_OBSERVED, 200)),
                "HTTP_OBSERVED 200 without explicit entryHit still may suspect via status");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.AUTH_CHALLENGE, 401, true, false)),
                "401 AUTH_CHALLENGE without effect is diagnostic UNREACHED, not suspected vuln");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.AUTH_CHALLENGE, 403, true, false)),
                "403 AUTH_CHALLENGE without effect is diagnostic UNREACHED");
        check(ApiDtos.DYNAMIC_SUSPECTED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.AUTH_CHALLENGE, 401, true, true)),
                "AUTH_CHALLENGE with effect/SQL signal may still be DYNAMIC_SUSPECTED");
    }

    private static void floodRatioGate() {
        int total = 2036;
        int invalid = 1935;
        double invalidRatio = (double) invalid / (double) total;
        check(invalidRatio > 0.90, "historical scan-7b619e noise ratio exceeds 90%");
        int suspectedFromInvalid = 0;
        for (int i = 0; i < invalid; i++) {
            String status = TraceProjectionService.verificationStatusFor(
                    PathOutcomeClass.UNKNOWN, -1);
            if (ApiDtos.DYNAMIC_SUSPECTED.equals(status)) {
                suspectedFromInvalid++;
            }
        }
        check(suspectedFromInvalid == 0,
                "invalid PathRun flood must produce zero DYNAMIC_SUSPECTED under P0-20 gate");
        check(invalidRatio <= 0.05 || suspectedFromInvalid == 0,
                "release gate: either invalid ratio <=5% or zero suspected from invalid rows");
    }

    private static void startupDiagnosticsClassify() {
        SandboxStartupDiagnostics.Diagnosis port =
                SandboxStartupDiagnostics.classify(70, "wait-http-ready failed ports=3306,6379");
        check(port.failureClass() == SandboxStartupDiagnostics.FailureClass.DEPENDENCY_PORT_MISCLASSIFIED
                        || port.failureClass() == SandboxStartupDiagnostics.FailureClass.PORT_NOT_LISTENING,
                "exit 70 classified as port/dependency readiness failure");
        SandboxStartupDiagnostics.Diagnosis probe =
                SandboxStartupDiagnostics.classify(71, "probe_jvm_status=3");
        check(probe.failureClass() == SandboxStartupDiagnostics.FailureClass.PROBE_JVM_FAILED,
                "exit 71 is PROBE_JVM_FAILED");
        check(SandboxStartupDiagnostics.isDependencyPort(3306), "3306 is dependency port");
        check(SandboxStartupDiagnostics.isDependencyPort(6379), "6379 is dependency port");
        check(SandboxStartupDiagnostics.isDependencyPort(5432), "5432 is dependency port");
        check(!SandboxStartupDiagnostics.isDependencyPort(8080), "8080 is not dependency port");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
