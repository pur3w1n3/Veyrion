package com.aq.jvmsentinel;

import org.junit.jupiter.api.Test;

/** Surefire entry point for the curated acceptance main gate. */
public final class AcceptanceTestGate {
    @Test
    void criticalAcceptanceMainsExecuteWithNonZeroAssertions() throws Exception {
        AcceptanceTestRunner.Result result = AcceptanceTestRunner.runGate();
        System.out.println("AcceptanceTestGate: executed=" + result.executed()
                + " assertions=" + result.assertions());
        if (result.executed() == 0 || result.assertions() == 0) {
            throw new AssertionError("Acceptance gate requires non-zero executed tests and assertions; "
                    + "executed=" + result.executed() + " assertions=" + result.assertions());
        }
        if (!result.failures().isEmpty()) {
            throw new AssertionError(String.join(System.lineSeparator(), result.failures()));
        }
    }
}
