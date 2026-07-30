package com.aq.jvmsentinel.sandbox;

import java.nio.file.Path;
import java.util.Objects;

/**
 * operator-owned 的 digest 校验、只读 artifact mount 请求。
 * sandbox backend 在 materialize mount 时必须校验 digest。
 */
public record ReadOnlyArtifactMount(Path source, String destination, String sha256, long sizeBytes) {
    public ReadOnlyArtifactMount {
        Objects.requireNonNull(source, "source");
        source = source.toAbsolutePath().normalize();
        if (!source.isAbsolute()) throw new IllegalArgumentException("artifact source must be absolute");
        destination = SandboxContracts.text(destination, "artifact destination", 4096);
        if (!destination.startsWith("/") || destination.contains("..")) {
            throw new IllegalArgumentException("artifact destination must be an absolute normalized sandbox path");
        }
        sha256 = SandboxContracts.sha256(sha256, "artifact sha256");
        if (sizeBytes <= 0) throw new IllegalArgumentException("artifact sizeBytes must be positive");
    }
}
