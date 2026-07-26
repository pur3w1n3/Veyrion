package com.aq.jvmsentinel.sandbox;

import com.aq.jvmsentinel.worker.WorkerCapability;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Local Docker backend for explicitly trusted, catalog-owned internal JARs.
 *
 * <p>This capability is separate from both fixture runc and release-gated hardened runtimes.
 * It never falls back to a host process. Docker's effective network, mount, identity, rootfs,
 * capability, tmpfs and resource policy is inspected before a handle is returned.</p>
 */
public final class LocalDockerTrustedSandboxClient implements SandboxRuntimeClient {
    /** Container-default identity (root for the trusted runtime image). Privileged listen ports like 80 must work. */
    private static final int SANDBOX_UID = 0;
    private static final int SANDBOX_GID = 0;
    private static final String TRACE_TMP = "/tmp/veyrion-trace";
    private static final int MAX_PROCESS_OUTPUT = 4 * 1024 * 1024;
    private static final int MAX_PIDS = 1_024;
    private static final Set<String> FEATURES = Set.of(
            "lifecycle-v1", "execd-command-v1", "network-deny-v1",
            "resource-budget-v1", "container-root-v1", "read-only-rootfs-v1",
            "writable-tmp-v1", "controlled-tmpfs-v1",
            "digest-pinned-readonly-artifact-v1");
    private static final RuntimeAttestation ATTESTATION = new RuntimeAttestation(
            "docker-cli-v1", WorkerCapability.TRUSTED_DOCKER, "docker-desktop-runc",
            true, true, true, FEATURES);

    private final String dockerExecutable;
    private final Map<String, SandboxRequest> sandboxes = new ConcurrentHashMap<>();

    public LocalDockerTrustedSandboxClient() {
        this("docker");
    }

    public LocalDockerTrustedSandboxClient(String dockerExecutable) {
        if (dockerExecutable == null || dockerExecutable.isBlank()
                || dockerExecutable.length() > 1024
                || dockerExecutable.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new IllegalArgumentException("dockerExecutable is invalid");
        }
        this.dockerExecutable = dockerExecutable;
    }

    @Override
    public SandboxHandle create(SandboxRequest request) {
        ReadOnlyArtifactMount mount = requireTrustedRequest(request);
        verifyArtifact(mount);
        String name = "veyrion-trusted-" + UUID.randomUUID().toString().replace("-", "");
        // Boundary: deny-all egress (--network none) + read-only rootfs + digest-pinned artifact.
        // Force root inside the container (image defaults to 65532) so JARs can bind privileged
        // ports like 80; do not strip capabilities for complete startup under loopback probing.
        List<String> command = new ArrayList<>(List.of(
                dockerExecutable, "run", "--detach", "--name", name,
                "--label", "com.veyrion.trusted-docker=true",
                "--network", "none",
                "--read-only",
                "--user", SANDBOX_UID + ":" + SANDBOX_GID,
                "--tmpfs", "/tmp/veyrion-trace:rw,nosuid,nodev,size=" + request.tmpfsBytes()
                        + ",mode=1777,uid=" + SANDBOX_UID + ",gid=" + SANDBOX_GID,
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--mount", "type=bind,source=" + mount.source()
                        + ",target=" + mount.destination() + ",readonly",
                "--pids-limit", Integer.toString(MAX_PIDS),
                "--memory", Long.toString(request.resourceBudget().maxMemoryBytes()),
                "--memory-swap", Long.toString(request.resourceBudget().maxMemoryBytes()),
                "--cpus", "1.0",
                "--entrypoint", request.entrypoint().get(0),
                request.image()));
        command.addAll(request.entrypoint().subList(1, request.entrypoint().size()));
        ProcessResult result = run(command, Duration.ofMinutes(5));
        if (result.exitCode() != 0) {
            throw failure("Docker failed to create the trusted artifact sandbox", result);
        }
        String containerId = result.stdout().strip();
        if (!containerId.matches("[0-9a-f]{64}")) {
            bestEffortDelete(name);
            throw new IllegalStateException("Docker returned an invalid container identifier");
        }
        try {
            verifyEffectivePolicy(containerId, request, mount);
            verifyTraceDirectory(containerId);
            if (sandboxes.putIfAbsent(containerId, request) != null) {
                throw new IllegalStateException("Docker reused a trusted sandbox identifier");
            }
            return new SandboxHandle(containerId,
                    new SandboxStatus(SandboxStatus.State.RUNNING, null, null), ATTESTATION);
        } catch (RuntimeException failure) {
            bestEffortDelete(containerId);
            throw failure;
        }
    }

    @Override
    public CommandResult command(String sandboxId, CommandRequest request) {
        requireKnown(sandboxId);
        if (request.uid() != SANDBOX_UID || request.gid() != SANDBOX_GID) {
            throw new SecurityException("trusted Docker commands require UID/GID 0:0");
        }
        ProcessResult result = run(List.of(
                dockerExecutable, "exec",
                "--user", SANDBOX_UID + ":" + SANDBOX_GID,
                "--workdir", request.workingDirectory(),
                sandboxId, "/bin/sh", "-c", request.command()),
                request.timeout().plusSeconds(5));
        return new CommandResult(null, result.stdout(), result.stderr(), result.exitCode());
    }

    @Override
    public void uploadFile(String sandboxId, Path hostFile, String containerPath) {
        requireKnown(sandboxId);
        Objects.requireNonNull(hostFile, "hostFile");
        // docker cp cannot write into --read-only rootfs containers even when the destination is
        // a writable tmpfs; stream bytes through docker exec into /tmp/veyrion-trace instead.
        if (containerPath == null
                || !containerPath.matches(TRACE_TMP + "/[A-Za-z0-9._-]{1,200}")
                || containerPath.contains("..")) {
            throw new SecurityException("upload path must stay under the sandbox trace tmpfs");
        }
        if (!Files.isRegularFile(hostFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(hostFile)) {
            throw new IllegalArgumentException("upload host file must be a regular non-link file");
        }
        try {
            long size = Files.size(hostFile);
            if (size <= 0 || size > 256 * 1024) {
                throw new IllegalArgumentException("upload host file size is outside trusted sandbox limits");
            }
        } catch (IOException failure) {
            throw new IllegalStateException("upload host file could not be inspected", failure);
        }
        ProcessResult result = runWithInput(List.of(
                dockerExecutable, "exec", "-i",
                "--user", SANDBOX_UID + ":" + SANDBOX_GID,
                sandboxId, "/bin/sh", "-c", "cat > '" + containerPath + "'"),
                hostFile.toAbsolutePath().normalize(),
                Duration.ofSeconds(30));
        if (result.exitCode() != 0) {
            throw failure("Docker failed to upload a file into the trusted artifact sandbox", result);
        }
    }

    @Override
    public void delete(String sandboxId) {
        requireKnown(sandboxId);
        ProcessResult result = run(List.of(dockerExecutable, "rm", "--force", sandboxId),
                Duration.ofSeconds(30));
        sandboxes.remove(sandboxId);
        if (result.exitCode() != 0) {
            throw failure("Docker failed to remove the trusted artifact sandbox", result);
        }
    }

    @Override
    public void close() {
        RuntimeException primary = null;
        for (String sandboxId : List.copyOf(sandboxes.keySet())) {
            try {
                delete(sandboxId);
            } catch (RuntimeException failure) {
                if (primary == null) primary = failure;
                else primary.addSuppressed(failure);
            }
        }
        if (primary != null) throw primary;
    }

    private void verifyEffectivePolicy(String sandboxId, SandboxRequest request,
                                       ReadOnlyArtifactMount mount) {
        ProcessResult result = run(List.of(dockerExecutable, "inspect", "--format",
                "{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|"
                        + "{{json .HostConfig.Tmpfs}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}|"
                        + "{{len .Mounts}}|{{(index .Mounts 0).Type}}|"
                        + "{{(index .Mounts 0).Destination}}|{{(index .Mounts 0).RW}}",
                sandboxId), Duration.ofSeconds(30));
        if (result.exitCode() != 0) throw failure("Docker inspection failed", result);
        String[] fields = result.stdout().strip().split("\\|", -1);
        boolean rootUser = "0:0".equals(fields[2]) || "0".equals(fields[2]) || "root".equals(fields[2]);
        if (fields.length != 10
                || !"none".equals(fields[0])
                || !"true".equalsIgnoreCase(fields[1])
                || !rootUser
                || !fields[3].contains("\"/tmp/veyrion-trace\"")
                || Long.parseLong(fields[4]) != request.resourceBudget().maxMemoryBytes()
                || Long.parseLong(fields[5]) <= 0 || Long.parseLong(fields[5]) > MAX_PIDS
                || !"1".equals(fields[6])
                || !"bind".equals(fields[7])
                || !mount.destination().equals(fields[8])
                || !"false".equalsIgnoreCase(fields[9])) {
            throw new SecurityException("effective Docker trusted-artifact policy did not match requirements");
        }
    }

    private void verifyTraceDirectory(String sandboxId) {
        ProcessResult probe = run(List.of(
                dockerExecutable, "exec", "--user", SANDBOX_UID + ":" + SANDBOX_GID, sandboxId,
                "/bin/sh", "-c",
                "id -u | grep -qx " + SANDBOX_UID
                        + " && ! touch /veyrion-rootfs-write-probe"
                        + " && touch /tmp/veyrion-trace/veyrion-tmpfs-probe"
                        + " && rm -f /tmp/veyrion-trace/agent-events.jsonl"),
                Duration.ofSeconds(15));
        if (probe.exitCode() != 0) {
            throw failure("Docker trace tmpfs policy probe failed", probe);
        }
    }

    private static ReadOnlyArtifactMount requireTrustedRequest(SandboxRequest request) {
        if (request == null || request.requiredCapability() != WorkerCapability.TRUSTED_DOCKER
                || request.readOnlyArtifacts().size() != 1
                || !request.image().matches("[a-z0-9.-]+(?::[0-9]{1,5})?"
                        + "(?:/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}")) {
            throw new SecurityException(
                    "local trusted Docker backend accepts one artifact and a digest-pinned image");
        }
        ReadOnlyArtifactMount mount = request.readOnlyArtifacts().get(0);
        if (mount.source().toString().contains(",") || mount.destination().contains(",")) {
            throw new SecurityException("artifact mount path cannot be represented safely by Docker");
        }
        return mount;
    }

    private static void verifyArtifact(ReadOnlyArtifactMount mount) {
        Path path = mount.source();
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || Files.isSymbolicLink(path)
                    || before.size() != mount.sizeBytes()) {
                throw new SecurityException("artifact identity or size changed before Docker mount");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileChannel channel = FileChannel.open(
                    path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
                while (channel.read(buffer) >= 0) {
                    buffer.flip();
                    digest.update(buffer);
                    buffer.clear();
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!sameFile(before, after)
                    || !MessageDigest.isEqual(digest.digest(), HexFormat.of().parseHex(mount.sha256()))) {
                throw new SecurityException("artifact changed during Docker mount verification");
            }
        } catch (IOException failure) {
            throw new IllegalStateException("artifact could not be verified before Docker mount", failure);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean sameFile(BasicFileAttributes before, BasicFileAttributes after) {
        if (!after.isRegularFile() || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) return false;
        return before.fileKey() == null || after.fileKey() == null
                || before.fileKey().equals(after.fileKey());
    }

    private SandboxRequest requireKnown(String sandboxId) {
        SandboxContracts.id(sandboxId, "sandboxId");
        SandboxRequest request = sandboxes.get(sandboxId);
        if (request == null) throw new SecurityException("trusted Docker sandbox is unknown");
        return request;
    }

    private void bestEffortDelete(String value) {
        try {
            run(List.of(dockerExecutable, "rm", "--force", value), Duration.ofSeconds(15));
        } catch (RuntimeException ignored) {
            // Preserve the primary policy or creation failure.
        }
    }

    private static IllegalStateException failure(String message, ProcessResult result) {
        String suffix = result.stderr().isBlank() ? "" : ": " + bounded(result.stderr(), 512);
        return new IllegalStateException(message + suffix);
    }

    private static ProcessResult run(List<String> command, Duration timeout) {
        return runWithInput(command, null, timeout);
    }

    private static ProcessResult runWithInput(List<String> command, Path stdinFile, Duration timeout) {
        Process process;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            if (stdinFile != null) {
                builder.redirectInput(stdinFile.toFile());
            }
            process = builder.start();
        } catch (IOException failure) {
            throw new IllegalStateException("Docker process could not be started", failure);
        }
        CompletableFuture<byte[]> stdout = CompletableFuture.supplyAsync(
                () -> readBounded(process.getInputStream()));
        CompletableFuture<byte[]> stderr = CompletableFuture.supplyAsync(
                () -> readBounded(process.getErrorStream()));
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new IllegalStateException("Docker process exceeded its deadline");
            }
            return new ProcessResult(process.exitValue(), decode(stdout.join()), decode(stderr.join()));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IllegalStateException("Docker process was interrupted", interrupted);
        }
    }

    private static byte[] readBounded(InputStream input) {
        try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (output.size() + count > MAX_PROCESS_OUTPUT) {
                    throw new IllegalStateException("Docker process output exceeded its limit");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } catch (IOException failure) {
            throw new IllegalStateException("Docker process output could not be read", failure);
        }
    }

    private static String decode(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static String bounded(String value, int maximum) {
        String normalized = value.replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", "?").strip();
        return normalized.length() <= maximum ? normalized : normalized.substring(0, maximum);
    }

    private record ProcessResult(int exitCode, String stdout, String stderr) { }
}
