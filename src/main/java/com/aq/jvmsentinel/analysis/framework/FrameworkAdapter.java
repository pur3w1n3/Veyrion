package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** SPI for framework-specific high-value route / auth heuristics. */
public interface FrameworkAdapter {
    String id();

    boolean matches(Path artifactPath, List<String> routes);

    Set<String> highValueRouteSignals();

    Set<String> highValueClassSignals();

    boolean preferBladeAuthHeader(SyntheticIdentityService.MaterialBundle materials);

    /**
     * Optional redacted harvest signal for dashboard/AI. Must not return raw commercial
     * defaults as if they were FACT; prefer {@link #jwtSecretHintNotes()} for HINT inject.
     */
    Optional<String> suggestJwtSecret(Path artifactPath);

    /**
     * Well-known / framework HINT notes for FRAMEWORK_ADAPTER_CONTEXT (not FACT, not mint).
     */
    default List<String> jwtSecretHintNotes() {
        return List.of();
    }

    List<AuthBypassTechnique> defaultBypassTechniques();
}
