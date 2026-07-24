package com.aq.jvmsentinel.sandbox;

/** OpenSandbox lifecycle status. Unknown future states are rejected rather than guessed. */
public record SandboxStatus(State state, String reason, String message) {
    public SandboxStatus {
        if (state == null) throw new NullPointerException("state");
        reason = optional(reason, "reason");
        message = optional(message, "message");
    }

    public enum State {
        PENDING, RUNNING, PAUSING, PAUSED, RESUMING, STOPPING, TERMINATED, FAILED
    }

    private static String optional(String value, String name) {
        if (value == null) return null;
        if (value.length() > 4096 || value.chars().anyMatch(c -> c < 0x20 && c != '\t')) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}
