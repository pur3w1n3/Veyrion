package com.aq.jvmsentinel;

import com.aq.jvmsentinel.decompile.*;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.util.List;
import java.util.stream.IntStream;

/** Main-style checks for the descriptive isolated-decompiler boundary. */
public final class DecompileBoundaryAcceptanceTest {
    private static final String ARTIFACT = "a".repeat(64);
    private static final String VINEFLOWER = "b".repeat(64);
    private static final String CFR = "c".repeat(64);

    public static void main(String[] args) throws Exception {
        DecompileWorkerRequest request = request();
        List<String> primary = DecompileCommandTemplate.arguments(request, DecompilerTool.VINEFLOWER, VINEFLOWER);
        check(primary.equals(List.of("/opt/java/bin/java", "-cp",
                "/opt/veyrion-tools/vineflower-1.0.jar",
                "org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler",
                "-dgs=1", "-rsy=1", "/input/original.jar", "/output/vineflower")),
                "Vineflower argv must be fixed and shell-free");
        List<String> validation = DecompileCommandTemplate.arguments(request, DecompilerTool.CFR, CFR);
        check(validation.get(3).equals("org.benf.cfr.reader.Main"), "CFR must be the fixed validation tool");
        expect(SecurityException.class, () ->
                DecompileCommandTemplate.arguments(request, DecompilerTool.VINEFLOWER, "d".repeat(64)));

        DecompileResult result = new DecompileResult(1, "decompile-1", ARTIFACT, VINEFLOWER, CFR,
                1_000, 500, 20, List.of(new DecompileResult.OutputFile(
                "example/App.java", 20, "e".repeat(64))), DecompileResult.Status.COMPLETED);
        result.verifyAgainst(request);

        expect(SecurityException.class, () -> new DecompileResult(1, "decompile-1", "f".repeat(64),
                VINEFLOWER, CFR, 1, 1, 0, List.of(), DecompileResult.Status.COMPLETED)
                .verifyAgainst(request));
        expect(IllegalArgumentException.class, () -> new DecompileResult(1, "decompile-1", ARTIFACT,
                VINEFLOWER, CFR, 61_000, 1, 0, List.of(), DecompileResult.Status.PARTIAL_BUDGET_EXCEEDED)
                .verifyAgainst(request));
        expect(IllegalArgumentException.class, () -> new DecompileResult(1, "decompile-1", ARTIFACT,
                VINEFLOWER, CFR, 1, 1, 32L * 1024 * 1024 + 1, List.of(),
                DecompileResult.Status.PARTIAL_BUDGET_EXCEEDED).verifyAgainst(request));
        List<DecompileResult.OutputFile> tooManyFiles = IntStream.range(0, 1_001)
                .mapToObj(index -> new DecompileResult.OutputFile(
                        "out/File" + index + ".java", 0, "e".repeat(64))).toList();
        expect(IllegalArgumentException.class, () -> new DecompileResult(1, "decompile-1", ARTIFACT,
                VINEFLOWER, CFR, 1, 1, 0, tooManyFiles,
                DecompileResult.Status.PARTIAL_BUDGET_EXCEEDED).verifyAgainst(request));
        expect(IllegalArgumentException.class, () ->
                new DecompileResult.OutputFile("../escape.java", 1, "e".repeat(64)));
        expect(IllegalArgumentException.class, () -> new DecompilerToolArtifact(1,
                DecompilerTool.VINEFLOWER, "1.0", VINEFLOWER, "/tmp/tool.jar"));
        expect(IllegalArgumentException.class, () -> new DecompileWorkerRequest(1, "project-1",
                "scan-1", "task-1", ARTIFACT, "/input/original.jar", true,
                NetworkPolicy.denyAll(), WorkerCapability.STATIC_ONLY, budget(), vineflower(), cfr()));
        expect(IllegalArgumentException.class, () -> new DecompileWorkerRequest(1, "project-1",
                "scan-1", "task-1", ARTIFACT, "/input/../host.jar", true,
                NetworkPolicy.denyAll(), WorkerCapability.HARDENED_GVISOR, budget(), vineflower(), cfr()));

        System.out.println("DecompileBoundaryAcceptanceTest: PASS");
    }

    private static DecompileWorkerRequest request() {
        return new DecompileWorkerRequest(1, "project-1", "scan-1", "decompile-1", ARTIFACT,
                DecompileWorkerRequest.ARTIFACT_PATH, true, NetworkPolicy.denyAll(),
                WorkerCapability.HARDENED_GVISOR, budget(), vineflower(), cfr());
    }

    private static DecompileBudget budget() {
        return new DecompileBudget(new ResourceBudget(60, 10_000, 256L * 1024 * 1024,
                64L * 1024 * 1024, 1024 * 1024), 1_000, 32L * 1024 * 1024);
    }

    private static DecompilerToolArtifact vineflower() {
        return new DecompilerToolArtifact(1, DecompilerTool.VINEFLOWER, "1.0", VINEFLOWER,
                "/opt/veyrion-tools/vineflower-1.0.jar");
    }

    private static DecompilerToolArtifact cfr() {
        return new DecompilerToolArtifact(1, DecompilerTool.CFR, "1.0", CFR,
                "/opt/veyrion-tools/cfr-1.0.jar");
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
