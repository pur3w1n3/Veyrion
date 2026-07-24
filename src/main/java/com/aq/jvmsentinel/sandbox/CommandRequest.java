package com.aq.jvmsentinel.sandbox;

import java.time.Duration;
import java.util.Objects;

/** Execd command request with mandatory non-root identity and no caller-supplied environment. */
public record CommandRequest(String command, String workingDirectory, Duration timeout, int uid, int gid) {
    public CommandRequest {
        command = SandboxContracts.text(command, "command", 65_536);
        workingDirectory = SandboxContracts.text(workingDirectory, "workingDirectory", 4096);
        if (!workingDirectory.startsWith("/") || workingDirectory.contains("..")) {
            throw new IllegalArgumentException("workingDirectory must be an absolute normalized sandbox path");
        }
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofHours(1)) > 0
                || timeout.toMillis() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("invalid command timeout");
        }
        if (uid <= 0 || gid <= 0) throw new IllegalArgumentException("execd commands require non-root UID and GID");
    }
}
