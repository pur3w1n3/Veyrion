package com.aq.jvmsentinel.analysis.pack;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Blade / SpringBlade default JWT credential experiment shapes (non-destructive). */
public final class BladeJwtCredentialPack implements AnalysisPack {
    public static final String DEFAULT_SECRET = "00000000000000000000000000000000";

    @Override
    public String id() {
        return "blade-jwt-default";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> entryRoutes) {
        if (entryRoutes == null) return false;
        for (String route : entryRoutes) {
            String value = route == null ? "" : route.toLowerCase(Locale.ROOT);
            if (value.contains("/blade-") || value.contains("/api/blade")
                    || value.contains("oauth") || value.contains("token")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        return Optional.of(DEFAULT_SECRET);
    }

    @Override
    public List<ExperimentPlan> experimentTemplates(String entrypointRef, IdentityTrack track) {
        return List.of(new ExperimentPlan(
                "plan-blade-jwt-" + track.name().toLowerCase(Locale.ROOT),
                entrypointRef,
                track,
                "GET",
                "application/json",
                List.of(),
                track != IdentityTrack.UNAUTH,
                "2xx",
                "$.code",
                2));
    }
}
