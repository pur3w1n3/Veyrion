package com.aq.jvmsentinel.policy;

import java.util.List;
import java.util.Objects;

public record ScanPolicy(boolean authorized, NetworkMode networkMode, DangerousActionMode dangerousActionMode,
                         List<String> networkAllowlist, long maxWallClockSeconds, long maxMemoryBytes,
                         long maxDiskBytes) {
    public ScanPolicy {
        Objects.requireNonNull(networkMode, "networkMode");
        Objects.requireNonNull(dangerousActionMode, "dangerousActionMode");
        networkAllowlist = List.copyOf(networkAllowlist == null ? List.of() : networkAllowlist);
        if (networkAllowlist.stream().anyMatch(value -> value == null || value.isBlank() || value.chars().anyMatch(Character::isWhitespace))) {
            throw new IllegalArgumentException("network allowlist entries must be non-blank and contain no whitespace");
        }
        if (maxWallClockSeconds <= 0 || maxMemoryBytes <= 0 || maxDiskBytes <= 0) {
            throw new IllegalArgumentException("resource limits must be positive");
        }
        if (networkMode == NetworkMode.DENY && !networkAllowlist.isEmpty()) {
            throw new IllegalArgumentException("network allowlist cannot be set when network is denied");
        }
    }

    public static ScanPolicy safeDefault() {
        return new ScanPolicy(false, NetworkMode.DENY, DangerousActionMode.DRY_RUN, List.of(), 900, 2L * 1024 * 1024 * 1024, 2L * 1024 * 1024 * 1024);
    }
}
