package com.aq.jvmsentinel.sandbox;

import java.time.Duration;
import java.util.Objects;

/**
 * 说明：Execd command request；Trusted Docker 以 container 默认 user（通常 root）运行，
 * 以便导入 JAR 绑定配置端口（含 privileged 如 80）。
 * 调用方提供的 environment 仍禁止。
 */
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
        if (uid < 0 || gid < 0 || uid > 65535 || gid > 65535) {
            throw new IllegalArgumentException("execd UID/GID must be in 0..65535");
        }
    }
}
