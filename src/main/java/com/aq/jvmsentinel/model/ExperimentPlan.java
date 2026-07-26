package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * AI-proposed, server-gated experiment plan for one entry × track.
 * Models propose; the server validates budget and safety before execution.
 */
public record ExperimentPlan(
        String planId,
        String entrypointRef,
        IdentityTrack track,
        String method,
        String contentType,
        List<String> requiredParameters,
        boolean authRequired,
        String successHttpHint,
        String successJsonPath,
        int maxAttempts
) {
    public ExperimentPlan {
        Objects.requireNonNull(planId, "planId");
        Objects.requireNonNull(entrypointRef, "entrypointRef");
        Objects.requireNonNull(track, "track");
        method = Objects.requireNonNullElse(method, "GET").toUpperCase();
        contentType = Objects.requireNonNullElse(contentType, "application/json");
        requiredParameters = List.copyOf(requiredParameters == null ? List.of() : requiredParameters);
        if (maxAttempts < 1 || maxAttempts > 8) {
            throw new IllegalArgumentException("maxAttempts must be 1..8");
        }
    }
}
