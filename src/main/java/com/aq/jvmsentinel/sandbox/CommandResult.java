package com.aq.jvmsentinel.sandbox;

/** Bounded foreground command result assembled from Execd JSON or SSE events. */
public record CommandResult(String commandId, String stdout, String stderr, int exitCode) {
    public CommandResult {
        if (commandId != null) commandId = SandboxContracts.id(commandId, "commandId");
        stdout = stdout == null ? "" : stdout;
        stderr = stderr == null ? "" : stderr;
        if (stdout.length() + stderr.length() > SandboxContracts.MAX_RESPONSE_BYTES) {
            throw new IllegalArgumentException("command output exceeds limit");
        }
    }
}
