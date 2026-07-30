package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 确保产品洪泛上限（512 探针）落在 documented trusted-sandbox
 * 上传预算内，超大计划在 Docker 上传前 fail-closed 并给出清晰消息。
 */
public final class ProbePlanUploadBudgetAcceptanceTest {
    private ProbePlanUploadBudgetAcceptanceTest() { }

    public static void main(String[] args) {
        check(ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES == 512, "flood entry ceiling");
        check(ProbePlanService.MAX_DYNAMIC_PROBES
                        == ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES,
                "control-plane probe count matches worker");
        check(ProbePlanService.MAX_PROBE_PLAN_UPLOAD_BYTES
                        == ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES,
                "control-plane upload budget matches worker");
        check(LocalDockerTrustedSandboxClient.MAX_UPLOAD_HOST_FILE_BYTES
                        == ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES,
                "sandbox upload ceiling matches probe-plan budget");
        check(ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES == 3 * 1024 * 1024,
                "documented 3 MiB probe-plan upload budget");

        List<ExternalArtifactTaskExecutor.ProbeTarget> flood = new ArrayList<>();
        String auth = "x".repeat(2048);
        String blade = "y".repeat(2048);
        String route = "/" + "r".repeat(1023);
        String query = "q=" + "v".repeat(252);
        for (int i = 0; i < ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES; i++) {
            flood.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    "DELETE", route, query, "BYPASS_CANDIDATE", auth, blade));
        }
        byte[] encoded = ExternalArtifactTaskExecutor.encodeProbePlan(flood);
        check(encoded.length > 256 * 1024, "worst-case 512-entry plan exceeds legacy 256 KiB cap");
        check(encoded.length <= ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES,
                "worst-case 512-entry plan fits raised upload budget");
        check(ExternalArtifactTaskExecutor.probePlanUtf8Bytes(flood) == encoded.length,
                "byte estimator matches encoder");

        List<ExternalArtifactTaskExecutor.ProbeTarget> oversize = new ArrayList<>(flood);
        oversize.add(new ExternalArtifactTaskExecutor.ProbeTarget("GET", "/overflow"));
        expectMessage(IllegalArgumentException.class, "probe plan exceeds entry limit",
                () -> ExternalArtifactTaskExecutor.encodeProbePlan(oversize));

        // 典型双 auth 洪泛（≈800 字节 header）须远低于预算。
        List<ExternalArtifactTaskExecutor.ProbeTarget> typical = new ArrayList<>();
        String typicalAuth = "Bearer " + "t".repeat(800);
        String typicalBlade = "u".repeat(800);
        for (int i = 0; i < ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES; i++) {
            typical.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    "GET", "/api/item/" + i, "id=" + i, "ADMIN", typicalAuth, typicalBlade));
        }
        byte[] typicalBytes = ExternalArtifactTaskExecutor.encodeProbePlan(typical);
        check(typicalBytes.length < ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES,
                "typical 512 dual-auth plan under budget");
        check(new String(typicalBytes, StandardCharsets.UTF_8).lines().count()
                        == ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_ENTRIES,
                "typical plan line count");

        System.out.println("ProbePlanUploadBudgetAcceptanceTest: PASS ("
                + "worst=" + encoded.length + "B, typical=" + typicalBytes.length + "B, budget="
                + ExternalArtifactTaskExecutor.MAX_PROBE_PLAN_UPLOAD_BYTES + "B)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void expectMessage(
            Class<? extends Throwable> type, String fragment, Runnable runnable) {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (!type.isInstance(actual)) {
                throw actual instanceof RuntimeException runtime ? runtime
                        : new RuntimeException(actual);
            }
            String message = actual.getMessage() == null ? "" : actual.getMessage();
            if (!message.contains(fragment)) {
                throw new AssertionError("expected message containing '" + fragment
                        + "' but was: " + message);
            }
            return;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }
}
