package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.policy.NetworkMode;

import java.util.List;
import java.util.Objects;
import java.util.HashSet;

/** Deny-by-default network contract. Allowlist entries are control-plane policy, not task payload data. */
public record NetworkPolicy(NetworkMode mode, List<String> allowlist) {
    public NetworkPolicy {
        Objects.requireNonNull(mode, "mode");
        allowlist = WorkerContracts.boundedCopy(allowlist, "allowlist");
        for (String entry : allowlist) {
            if (entry.isBlank() || entry.length() > 253 || entry.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("invalid network allowlist entry");
            }
        }
        if (new HashSet<>(allowlist).size() != allowlist.size()) {
            throw new IllegalArgumentException("network allowlist entries must be unique");
        }
        if (mode == NetworkMode.DENY && !allowlist.isEmpty()) {
            throw new IllegalArgumentException("DENY network mode cannot have an allowlist");
        }
        if (mode == NetworkMode.ALLOWLIST && allowlist.isEmpty()) {
            throw new IllegalArgumentException("ALLOWLIST network mode requires entries");
        }
    }

    public static NetworkPolicy denyAll() {
        return new NetworkPolicy(NetworkMode.DENY, List.of());
    }
}
