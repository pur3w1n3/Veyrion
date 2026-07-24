package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.sandbox.ReadOnlyArtifactMount;
import com.aq.jvmsentinel.sandbox.SandboxRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/** Focused contract checks that do not require Control Plane integration or a Docker daemon. */
public final class TrustedDockerBuildingBlocksAcceptanceTest {
    private static final String IMAGE =
            "registry.example/veyrion/runtime@sha256:" + "c".repeat(64);
    private static final String DIGEST = "a".repeat(64);
    private static final ResourceBudget BUDGET = new ResourceBudget(
            60, 30_000, 256L * 1024 * 1024, 64L * 1024 * 1024, 1024L * 1024);

    private TrustedDockerBuildingBlocksAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        WorkerTaskSpec trusted = task(false, NetworkPolicy.denyAll());
        check(trusted.requiredCapability() == WorkerCapability.TRUSTED_DOCKER,
                "trusted capability accepted");
        expect(IllegalArgumentException.class, () -> task(true, NetworkPolicy.denyAll()));
        expect(IllegalArgumentException.class, () -> new WorkerTaskSpec(
                1, "project-1", DIGEST, "scan-1", "task-denied", "entry-1",
                false, false, BUDGET, NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER));
        expect(IllegalArgumentException.class, () -> task(false,
                new NetworkPolicy(NetworkMode.ALLOWLIST, List.of("example.invalid"))));

        Path jar = Files.createTempFile("veyrion-trusted-contract-", ".jar");
        try {
            Files.write(jar, new byte[]{'P', 'K', 3, 4, 1});
            String digest = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)));
            ReadOnlyArtifactMount mount = new ReadOnlyArtifactMount(
                    jar, "/opt/veyrion/artifact/application.jar", digest, Files.size(jar));
            SandboxRequest request = new SandboxRequest(
                    IMAGE, List.of("/bin/sleep", "infinity"), 60, BUDGET, false,
                    WorkerCapability.TRUSTED_DOCKER, List.of(mount), BUDGET.maxDiskBytes());
            check(request.readOnlyArtifacts().size() == 1, "one read-only mount accepted");
            expect(IllegalArgumentException.class, () -> new SandboxRequest(
                    IMAGE, List.of("/bin/sleep", "infinity"), 60, BUDGET, false,
                    WorkerCapability.TRUSTED_DOCKER, List.of(), BUDGET.maxDiskBytes()));

            ReadOnlyArtifactMount wrongDigest = new ReadOnlyArtifactMount(
                    jar, mount.destination(), "f".repeat(64), Files.size(jar));
            SandboxRequest tampered = new SandboxRequest(
                    IMAGE, List.of("/bin/sleep", "infinity"), 60, BUDGET, false,
                    WorkerCapability.TRUSTED_DOCKER, List.of(wrongDigest), BUDGET.maxDiskBytes());
            LocalDockerTrustedSandboxClient client =
                    new LocalDockerTrustedSandboxClient("docker-executable-must-not-run");
            expect(SecurityException.class, () -> client.create(tampered));
        } finally {
            Files.deleteIfExists(jar);
        }
        System.out.println("TrustedDockerBuildingBlocksAcceptanceTest: PASS");
    }

    private static WorkerTaskSpec task(boolean fixtureOnly, NetworkPolicy networkPolicy) {
        return new WorkerTaskSpec(
                1, "project-1", DIGEST, "scan-1", "task-1", "entry-1",
                true, fixtureOnly, BUDGET, networkPolicy, WorkerCapability.TRUSTED_DOCKER);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static <T extends Throwable> void expect(
            Class<T> type, ThrowingRunnable runnable) throws Exception {
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
