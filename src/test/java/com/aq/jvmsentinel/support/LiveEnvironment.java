package com.aq.jvmsentinel.support;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Shared detection helpers for optional live Docker / DB / provider suites. */
public final class LiveEnvironment {
    private LiveEnvironment() {
    }

    public static boolean dockerAvailable() {
        for (int attempt = 0; attempt < 3; attempt++) {
            CommandResult result = run(
                    List.of("docker", "info", "--format", "{{.ServerVersion}}"),
                    Duration.ofSeconds(20));
            if (result.exitCode() == 0 && !result.stdout().isBlank()) {
                return true;
            }
            try {
                Thread.sleep(500L * (attempt + 1));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /**
     * 说明：Digest-pinned TRUSTED_DOCKER runtime image，不可用时空白。
     * 顺序：{@code VEYRION_DOCKER_RUNTIME_IMAGE}，再 local sandbox-pack tag digest。
     */
    public static String resolveTrustedDockerImage() {
        String fromEnv = System.getenv("VEYRION_DOCKER_RUNTIME_IMAGE");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.trim();
        }
        for (String ref : List.of(
                "127.0.0.1:5000/veyrion/artifact-runtime:dev",
                "veyrion/artifact-runtime:dev")) {
            CommandResult inspect = run(List.of(
                    "docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", ref),
                    Duration.ofSeconds(15));
            if (inspect.exitCode() == 0) {
                String digest = inspect.stdout().strip();
                if (digest.matches(".+@sha256:[0-9a-f]{64}")) {
                    return digest;
                }
            }
        }
        return "";
    }

    public static boolean postgresImageAvailable() {
        return run(List.of("docker", "image", "inspect", "postgres:15"), Duration.ofSeconds(10))
                .exitCode() == 0
                || run(List.of("docker", "image", "inspect", "postgres:18-alpine"),
                Duration.ofSeconds(10)).exitCode() == 0;
    }

    public static String preferredPostgresImage() {
        if (run(List.of("docker", "image", "inspect", "postgres:15"), Duration.ofSeconds(10))
                .exitCode() == 0) {
            return "postgres:15";
        }
        if (run(List.of("docker", "image", "inspect", "postgres:18-alpine"), Duration.ofSeconds(10))
                .exitCode() == 0) {
            return "postgres:18-alpine";
        }
        return "";
    }

    public static boolean liveProviderEnabled() {
        String value = System.getenv("VEYRION_LIVE_PROVIDER");
        return value != null && ("1".equals(value.trim()) || "true".equalsIgnoreCase(value.trim()));
    }

    public static CommandResult run(List<String> command, Duration timeout) {
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            CompletableFuture<String> outputFuture = CompletableFuture.supplyAsync(
                    () -> readBounded(process.getInputStream(), 64 * 1024));
            boolean finished = process.waitFor(Math.max(1L, timeout.toMillis()), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(3, TimeUnit.SECONDS);
                String partial = outputFuture.getNow("");
                return new CommandResult(124, partial == null ? "" : partial, "timeout");
            }
            String output = outputFuture.get(3, TimeUnit.SECONDS);
            return new CommandResult(process.exitValue(), output == null ? "" : output, "");
        } catch (Exception failure) {
            return new CommandResult(127, "", failure.getClass().getSimpleName() + ": "
                    + String.valueOf(failure.getMessage()).toLowerCase(Locale.ROOT));
        }
    }

    private static String readBounded(InputStream in, int maxBytes) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = in.read(chunk)) >= 0) {
                int allowed = Math.min(read, maxBytes - buffer.size());
                if (allowed > 0) {
                    buffer.write(chunk, 0, allowed);
                }
                if (buffer.size() >= maxBytes) {
                    // Drain 剩余，避免子进程被满 pipe 阻塞。
                    while (in.read(chunk) >= 0) {
                        // discard
                    }
                    break;
                }
            }
            return buffer.toString(StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return "";
        }
    }

    public static CommandResult docker(List<String> args, Duration timeout) {
        List<String> command = new ArrayList<>(args.size() + 1);
        command.add("docker");
        command.addAll(args);
        return run(command, timeout);
    }

    public record CommandResult(int exitCode, String stdout, String detail) {
        public String stdout() {
            return stdout == null ? "" : stdout;
        }
    }
}
