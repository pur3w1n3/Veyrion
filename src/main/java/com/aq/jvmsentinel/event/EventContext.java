package com.aq.jvmsentinel.event;

import java.util.Objects;

/** Stable scope identifiers carried by events exchanged between control-plane components. */
public record EventContext(String projectId, String artifactDigest, String scanId, String taskId) {
    public EventContext {
        requireText(projectId, "projectId");
        requireText(artifactDigest, "artifactDigest");
        requireText(scanId, "scanId");
        requireText(taskId, "taskId");
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) throw new IllegalArgumentException(name + " cannot be blank");
    }
}
