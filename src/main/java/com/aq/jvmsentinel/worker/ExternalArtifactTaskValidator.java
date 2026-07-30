package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.worker.docker.SandboxLaunchCommandBuilder;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

/**
 * 外部制品任务描述符、预算与制品摘要的 fail-closed 校验。
 */
final class ExternalArtifactTaskValidator {
    private ExternalArtifactTaskValidator() { }

    static void validateDescriptor(WorkerControlPlaneClient.TaskDescriptor value,
                                   TaskScope expectedScope, TaskLifecycle expectedLifecycle) {
        if (!value.scope().equals(expectedScope) || value.lifecycle() != expectedLifecycle) {
            throw new SecurityException("task response changed execution identity or lifecycle");
        }
        if (!value.authorized()) {
            throw new SecurityException("external artifact execution requires an authorized task");
        }
        if (value.requiredCapability() != WorkerCapability.TRUSTED_DOCKER
                && value.requiredCapability() != WorkerCapability.HARDENED_GVISOR
                && value.requiredCapability() != WorkerCapability.HARDENED_KATA) {
            throw new SecurityException("external artifact execution requires an approved artifact runtime");
        }
        if (value.networkPolicy().mode() != NetworkMode.DENY
                || !value.networkPolicy().allowlist().isEmpty()) {
            throw new SecurityException("external artifact execution requires deny-all network policy");
        }
    }

    /**
     * complete 可能 fail-closed 进入 FAILED（如 PROJECTION_FAILED）且 scope 不变。
     * 需与 lease/start 身份不匹配区分，避免误读。
     */
    static void requireCompletedDescriptor(WorkerControlPlaneClient.TaskDescriptor value,
                                           TaskScope expectedScope,
                                           WorkerControlPlaneClient.TaskDescriptor baseline) {
        if (!value.scope().equals(expectedScope)) {
            throw new SecurityException("task response changed execution identity or lifecycle");
        }
        if (value.lifecycle() == TaskLifecycle.FAILED) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "PROJECTION_OR_COMPLETE_FAILED",
                    "control plane rejected task completion (lifecycle=FAILED); "
                            + "inspect /scans/{scanId}/dynamic-tasks failureDiagnostic",
                    null);
        }
        validateDescriptor(value, expectedScope, TaskLifecycle.COMPLETED);
        requireStableDescriptor(baseline, value);
    }

    static void validateRegistration(ExternalArtifactTaskExecutor.ArtifactRegistration value,
                                     TaskScope scope) {
        Objects.requireNonNull(value, "artifact registration");
        if (!value.projectId().equals(scope.projectId()) || !value.sha256().equals(scope.artifactDigest())) {
            throw new SecurityException("artifact registration is not bound to the task scope");
        }
        if (!value.executableSpringBootJar()) {
            throw new SecurityException("registered artifact is not an executable Spring Boot JAR");
        }
        if (!value.path().getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
            throw new SecurityException("registered external artifact is not a JAR");
        }
    }

    static void requireStableDescriptor(WorkerControlPlaneClient.TaskDescriptor expected,
                                        WorkerControlPlaneClient.TaskDescriptor actual) {
        if (!expected.scope().equals(actual.scope())
                || !expected.targetEntryId().equals(actual.targetEntryId())
                || expected.authorized() != actual.authorized()
                || expected.requiredCapability() != actual.requiredCapability()
                || !expected.resourceBudget().equals(actual.resourceBudget())
                || !expected.networkPolicy().equals(actual.networkPolicy())) {
            throw new SecurityException("task response changed the immutable execution policy");
        }
    }

    static void validateBudget(ResourceBudget budget) {
        if (budget.maxWallClockSeconds() < 60
                || budget.maxWallClockSeconds() > ExternalArtifactPaths.MAX_WALL_SECONDS
                || budget.maxCpuMillis() > ExternalArtifactPaths.MAX_CPU_MILLIS
                || budget.maxCpuMillis() > budget.maxWallClockSeconds() * 1_000
                || budget.maxMemoryBytes() < 64L * 1024 * 1024
                || budget.maxMemoryBytes() > ExternalArtifactPaths.MAX_MEMORY_BYTES
                || budget.maxDiskBytes() < 1024L * 1024
                || budget.maxDiskBytes() > ExternalArtifactPaths.MAX_DISK_BYTES
                || budget.maxTraceBytes() < 256
                || budget.maxTraceBytes() > ExternalArtifactPaths.MAX_TRACE_BYTES
                || budget.maxDiskBytes() < SandboxLaunchCommandBuilder
                        .resolveTraceTmpfsBytes(budget.maxTraceBytes())) {
            throw new SecurityException("external artifact resource budget is outside hardened limits");
        }
    }

    static void recheckDigest(ExternalArtifactTaskExecutor.ArtifactRegistration registration) {
        Path path = registration.path();
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || Files.isSymbolicLink(path)
                    || before.size() <= 0 || before.size() > ExternalArtifactPaths.MAX_ARTIFACT_BYTES
                    || before.size() != registration.sizeBytes()) {
                throw new SecurityException("registered artifact file identity or size changed");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] signature = new byte[4];
            int signatureLength = 0;
            try (FileChannel channel = FileChannel.open(
                    path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
                while (channel.read(buffer) >= 0) {
                    buffer.flip();
                    while (buffer.hasRemaining()) {
                        byte value = buffer.get();
                        if (signatureLength < signature.length) signature[signatureLength++] = value;
                        digest.update(value);
                    }
                    buffer.clear();
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (signatureLength != 4 || signature[0] != 'P' || signature[1] != 'K'
                    || !sameFile(before, after) || after.size() != registration.sizeBytes()) {
                throw new SecurityException("registered JAR changed during digest verification");
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (!MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    registration.sha256().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new SecurityException("registered artifact digest no longer matches");
            }
        } catch (IOException exception) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "ARTIFACT_DIGEST_RECHECK_FAILED", "registered artifact could not be reverified", exception);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean sameFile(BasicFileAttributes before, BasicFileAttributes after) {
        if (!after.isRegularFile() || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) return false;
        return before.fileKey() == null || after.fileKey() == null || before.fileKey().equals(after.fileKey());
    }

    static void requireLease(WorkerLease lease, TaskScope scope, WorkerCapability capability,
                           String workerId) {
        if (!lease.scope().equals(scope) || !lease.workerId().equals(workerId)
                || lease.capability() != capability) {
            throw new SecurityException("lease binding does not match external artifact execution");
        }
    }
}
