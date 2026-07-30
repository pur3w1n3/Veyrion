package com.aq.jvmsentinel.decompile;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** 隔离 Worker 返回的有界结果 manifest；不嵌入源码内容。 */
public record DecompileResult(int schemaVersion, String taskId, String artifactDigest,
                              String primaryToolDigest, String validationToolDigest,
                              long wallClockMillis, long cpuMillis, long outputBytes,
                              List<OutputFile> files, Status status) {
    public static final int SCHEMA_VERSION = 1;

    public DecompileResult {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        Objects.requireNonNull(taskId, "taskId");
        artifactDigest = DecompileWorkerRequest.digest(artifactDigest, "artifactDigest");
        primaryToolDigest = DecompileWorkerRequest.digest(primaryToolDigest, "primaryToolDigest");
        validationToolDigest = DecompileWorkerRequest.digest(validationToolDigest, "validationToolDigest");
        if (wallClockMillis < 0 || cpuMillis < 0 || outputBytes < 0) {
            throw new IllegalArgumentException("usage values cannot be negative");
        }
        files = List.copyOf(Objects.requireNonNull(files, "files"));
        Objects.requireNonNull(status, "status");
        if (new HashSet<>(files.stream().map(OutputFile::relativePath).toList()).size() != files.size()) {
            throw new IllegalArgumentException("duplicate output path");
        }
    }

    public void verifyAgainst(DecompileWorkerRequest request) {
        Objects.requireNonNull(request, "request");
        if (!taskId.equals(request.taskId()) || !artifactDigest.equals(request.artifactDigest())
                || !primaryToolDigest.equals(request.primaryTool().sha256())
                || !validationToolDigest.equals(request.validationTool().sha256())) {
            throw new SecurityException("decompilation result scope or digest mismatch");
        }
        DecompileBudget limit = request.budget();
        if (wallClockMillis > limit.resources().maxWallClockSeconds() * 1000L
                || cpuMillis > limit.resources().maxCpuMillis()
                || outputBytes > limit.maxOutputBytes()
                || outputBytes > limit.resources().maxDiskBytes()
                || files.size() > limit.maxOutputFiles()) {
            throw new IllegalArgumentException("decompilation result exceeded its budget");
        }
        long manifestBytes = 0;
        try {
            for (OutputFile file : files) manifestBytes = Math.addExact(manifestBytes, file.sizeBytes());
        } catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("output manifest size overflow");
        }
        if (manifestBytes != outputBytes) {
            throw new IllegalArgumentException("output manifest size mismatch");
        }
    }

    public record OutputFile(String relativePath, long sizeBytes, String sha256) {
        public OutputFile {
            Objects.requireNonNull(relativePath, "relativePath");
            if (relativePath.isBlank() || relativePath.length() > 1024 || relativePath.startsWith("/")
                    || relativePath.startsWith("\\") || relativePath.contains("..")
                    || relativePath.indexOf('\\') >= 0 || relativePath.chars().anyMatch(c -> c < 0x20)) {
                throw new IllegalArgumentException("output path must be normalized and relative");
            }
            if (sizeBytes < 0) throw new IllegalArgumentException("negative output size");
            sha256 = DecompileWorkerRequest.digest(sha256, "output sha256");
        }
    }

    public enum Status {
        COMPLETED,
        PARTIAL_BUDGET_EXCEEDED,
        FAILED
    }
}
