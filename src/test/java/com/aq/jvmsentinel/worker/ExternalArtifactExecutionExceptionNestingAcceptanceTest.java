package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;

/**
 * 证明 ExternalArtifactExecutionException.of 不再自递归套娃。
 */
public final class ExternalArtifactExecutionExceptionNestingAcceptanceTest {
    private ExternalArtifactExecutionExceptionNestingAcceptanceTest() { }

    public static void main(String[] args) {
        AcceptanceAssertions.reset();

        IllegalStateException root = new IllegalStateException("root-cause");
        ExternalArtifactTaskExecutor.ExternalArtifactExecutionException first =
                ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_READ_FAILED", "trace could not be read safely", root);
        check(first.code().equals("TRACE_READ_FAILED"), "first wrap keeps failure code");
        check(first.getCause() == root, "first wrap keeps original root cause");
        check(depth(first) == 1, "first wrap has single ExternalArtifactExecutionException frame");

        ExternalArtifactTaskExecutor.ExternalArtifactExecutionException second =
                ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "EXTERNAL_ARTIFACT_EXECUTION_FAILED", "should not rewrap", first);
        check(second == first, "of() must not rewrap existing ExternalArtifactExecutionException");
        check(second.getCause() == root, "rewrapped call still exposes original root cause");
        check(depth(second) == 1, "cause chain must not nest ExternalArtifactExecutionException");

        ExternalArtifactTaskExecutor.ExternalArtifactExecutionException nullCause =
                ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_TOO_LARGE", "Agent trace exceeds the task budget", null);
        check(nullCause.getCause() == null, "null cause remains null");
        check(nullCause.code().equals("TRACE_TOO_LARGE"), "null-cause path keeps failure code");

        System.out.println("ExternalArtifactExecutionExceptionNestingAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static int depth(Throwable failure) {
        int count = 0;
        for (Throwable cursor = failure; cursor != null; cursor = cursor.getCause()) {
            if (cursor instanceof ExternalArtifactTaskExecutor.ExternalArtifactExecutionException) {
                count++;
            }
        }
        return count;
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
        AcceptanceAssertions.record();
    }
}
