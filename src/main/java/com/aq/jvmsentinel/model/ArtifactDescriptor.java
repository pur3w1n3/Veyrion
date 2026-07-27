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
        Instant registeredAt,
        String originalFileName) {
    public ArtifactDescriptor {
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(normalizedPath, "normalizedPath");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(registeredAt, "registeredAt");
        if (artifactId.isBlank() || !normalizedPath.isAbsolute() || sizeBytes < 0 || !sha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("invalid artifact descriptor");
        }
        originalFileName = sanitizeOriginalFileName(originalFileName);
    }

    /** Prefer the original upload/path basename for UI labels. */
    public String displayName() {
        return originalFileName != null ? originalFileName : artifactId;
    }

    public static String sanitizeOriginalFileName(String fileName) {
        if (fileName == null) return null;
        String trimmed = fileName.trim();
        if (trimmed.isBlank() || trimmed.length() > 255
                || trimmed.contains("/") || trimmed.contains("\\")
                || trimmed.equals(".") || trimmed.equals("..")
                || trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid originalFileName");
        }
        return trimmed;
    }
}
