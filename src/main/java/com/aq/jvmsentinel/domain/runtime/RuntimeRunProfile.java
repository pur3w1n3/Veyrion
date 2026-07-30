package com.aq.jvmsentinel.domain.runtime;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 服务端固定的 RuntimeAdapter run profile（P1-07）。
 *
 * <p>command template、image digest、mount、UID、network mode 与 budget 仅由
 * Control Plane 注册 template 产生。Model/frontend/Analyzer 字符串不能提供。
 */
public record RuntimeRunProfile(
        int schemaVersion,
        String runtimeKind,
        String runtimeVersion,
        String imageDigest,
        List<String> commandTemplate,
        List<ReadOnlyMount> readOnlyMounts,
        int uid,
        NetworkMode networkMode,
        RuntimeBudget budget,
        List<String> allowedObservationKinds,
        String maxVerificationStatus
) {
    public static final int SCHEMA_VERSION = 1;
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    public enum NetworkMode {
        DENY,
        ALLOWLIST
    }

    public RuntimeRunProfile {
        if (schemaVersion != SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported schemaVersion");
        }
        runtimeKind = requireId(runtimeKind, "runtimeKind");
        runtimeVersion = requireId(runtimeVersion, "runtimeVersion");
        imageDigest = requireDigest(imageDigest, "imageDigest");
        Objects.requireNonNull(commandTemplate, "commandTemplate");
        if (commandTemplate.isEmpty()) {
            throw new IllegalArgumentException("commandTemplate required");
        }
        commandTemplate = List.copyOf(commandTemplate);
        for (String arg : commandTemplate) {
            if (arg == null || arg.isBlank()) {
                throw new IllegalArgumentException("commandTemplate entries must be non-blank");
            }
        }
        readOnlyMounts = List.copyOf(readOnlyMounts == null ? List.of() : readOnlyMounts);
        if (uid < 1) {
            throw new IllegalArgumentException("uid must be positive non-root operator choice");
        }
        Objects.requireNonNull(networkMode, "networkMode");
        Objects.requireNonNull(budget, "budget");
        allowedObservationKinds = List.copyOf(
                allowedObservationKinds == null ? List.of() : allowedObservationKinds);
        maxVerificationStatus = normalizeMaxStatus(maxVerificationStatus);
    }

    /**
     * 仅 Control Plane template 使用的 factory。
     */
    public static RuntimeRunProfile serverFixed(
            String runtimeKind,
            String runtimeVersion,
            String imageDigest,
            List<String> commandTemplate,
            List<ReadOnlyMount> mounts,
            int uid,
            NetworkMode networkMode,
            RuntimeBudget budget,
            List<String> observationKinds,
            String maxVerificationStatus
    ) {
        return new RuntimeRunProfile(
                SCHEMA_VERSION,
                runtimeKind,
                runtimeVersion,
                imageDigest,
                commandTemplate,
                mounts,
                uid,
                networkMode,
                budget,
                observationKinds,
                maxVerificationStatus);
    }

    private static String normalizeMaxStatus(String status) {
        if (status == null || status.isBlank()) {
            return "DYNAMIC_SUSPECTED";
        }
        String normalized = status.trim();
        if ("VERIFIED".equals(normalized)) {
            throw new IllegalArgumentException("VERIFIED is not allowed on RuntimeRunProfile");
        }
        return switch (normalized) {
            case "STATIC_INFERRED", "DYNAMIC_SUSPECTED", "DYNAMIC_CONFIRMED", "UNREACHED" -> normalized;
            default -> throw new IllegalArgumentException("unsupported maxVerificationStatus");
        };
    }

    private static String requireId(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!ID.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " invalid");
        }
        return value;
    }

    private static String requireDigest(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!SHA256.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be lowercase SHA-256");
        }
        return value;
    }

    public record ReadOnlyMount(String sourceDigest, String targetPath, boolean readOnly) {
        public ReadOnlyMount {
            sourceDigest = requireDigest(sourceDigest, "sourceDigest");
            Objects.requireNonNull(targetPath, "targetPath");
            if (targetPath.isBlank()) {
                throw new IllegalArgumentException("targetPath required");
            }
            if (!readOnly) {
                throw new IllegalArgumentException("RuntimeAdapter mounts must be read-only");
            }
        }
    }

    public record RuntimeBudget(
            long maxWallClockSeconds,
            long maxCpuMillis,
            long maxMemoryBytes,
            long maxDiskBytes,
            long maxTraceBytes
    ) {
        public RuntimeBudget {
            if (maxWallClockSeconds < 1 || maxCpuMillis < 1 || maxMemoryBytes < 1
                    || maxDiskBytes < 1 || maxTraceBytes < 1) {
                throw new IllegalArgumentException("budget fields must be positive");
            }
        }
    }
}
