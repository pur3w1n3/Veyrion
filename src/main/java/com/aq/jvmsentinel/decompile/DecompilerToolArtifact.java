package com.aq.jvmsentinel.decompile;

import java.util.Objects;

/** 运维预置、digest 固定的 tool artifact；不打包也不加载 tool。 */
public record DecompilerToolArtifact(int schemaVersion, DecompilerTool tool, String version,
                                     String sha256, String sandboxJarPath) {
    public static final int SCHEMA_VERSION = 1;

    public DecompilerToolArtifact {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        Objects.requireNonNull(tool, "tool");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(sandboxJarPath, "sandboxJarPath");
        if (!version.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("invalid tool version");
        }
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("tool artifact must use a lowercase SHA-256");
        }
        String expectedPath = "/opt/veyrion-tools/" + tool.name().toLowerCase() + "-" + version + ".jar";
        if (!sandboxJarPath.equals(expectedPath)) {
            throw new IllegalArgumentException("tool path is outside the fixed sandbox tool directory");
        }
    }
}
