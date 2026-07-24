package com.aq.jvmsentinel.model;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;

public record ArtifactDescriptor(
        String artifactId,
        ArtifactType type,
        Path normalizedPath,
        long sizeBytes,
        String sha256,
        boolean staticOnly,
        Instant registeredAt) {
    public ArtifactDescriptor {
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(normalizedPath, "normalizedPath");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(registeredAt, "registeredAt");
        if (artifactId.isBlank() || !normalizedPath.isAbsolute() || sizeBytes < 0 || !sha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("invalid artifact descriptor");
        }
    }
}
