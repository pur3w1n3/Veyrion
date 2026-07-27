package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * SPI for optional framework-specific route / auth <em>hints</em>.
 * Adapters contribute signals only; the control plane, identity mint path, and AUTH
 * pipeline remain JVM-generic and must not treat any single framework as first-class.
 */
public interface FrameworkAdapter {
    String id();

    boolean matches(Path artifactPath, List<String> routes);

    Set<String> highValueRouteSignals();

    Set<String> highValueClassSignals();

    /**
     * When true, probes may dual-write a secondary auth header channel in addition to
     * {@code Authorization}. Header name comes from {@link #secondaryAuthHeaderName()}.
     */
    boolean preferSecondaryAuthHeader(SyntheticIdentityService.MaterialBundle materials);

    /**
     * Suggested secondary HTTP header name (e.g. {@code Blade-Auth}) when
     * {@link #preferSecondaryAuthHeader} is true; empty means Authorization-only.
     */
    default String secondaryAuthHeaderName() {
        return "";
    }

    /**
     * Optional adapter-owned detection dictionary for known weak / historical sign-key
     * strings. Used only when the same bytes appear inside the authorized artifact;
     * never a silent mint source. Classification remains RULE_GENERATED / HINT.
     */
    default List<AuthCodeQueryService.WellKnownKey> wellKnownSecretHints() {
        return List.of();
    }

    /**
     * Additional archive path fragments that hint this adapter's auth surface
     * (e.g. {@code org/springblade/core/secure}). Merged into generic code_query scans.
     */
    default Set<String> authClassPathSignals() {
        return Set.of();
    }

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

    /** @deprecated Use {@link #preferSecondaryAuthHeader}; Blade-named SPI retained for tests. */
    @Deprecated
    default boolean preferBladeAuthHeader(SyntheticIdentityService.MaterialBundle materials) {
        return preferSecondaryAuthHeader(materials);
    }
}
