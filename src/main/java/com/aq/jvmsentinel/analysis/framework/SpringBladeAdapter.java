package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * SpringBlade / BladeX surface heuristics.
 *
 * <p>{@link #suggestJwtSecret} does <em>not</em> return commercial defaults for silent minting.
 * Well-known aliases are HINT-only via {@link #jwtSecretHintNotes()}; AI must call
 * {@code code_query} to harvest material from the authorized artifact.
 */
public final class SpringBladeAdapter implements FrameworkAdapter {
    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "blade-", "bladex", "/blade-", "oauth", "token");
    private static final Set<String> CLASS_SIGNALS = Set.of(
            "blade", "bladex", "org.springblade");

    @Override
    public String id() {
        return "spring-blade";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> routes) {
        if (routes != null) {
            for (String route : routes) {
                if (containsAny(route, ROUTE_SIGNALS)) return true;
            }
        }
        if (artifactPath != null) {
            String name = artifactPath.getFileName() == null
                    ? "" : artifactPath.getFileName().toString().toLowerCase(Locale.ROOT);
            if (name.contains("blade") || name.contains("bladex")) return true;
        }
        return false;
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return ROUTE_SIGNALS;
    }

    @Override
    public Set<String> highValueClassSignals() {
        return CLASS_SIGNALS;
    }

    @Override
    public boolean preferBladeAuthHeader(SyntheticIdentityService.MaterialBundle materials) {
        // Framework-level HINT: Blade typically dual-channels Blade-Auth.
        if (materials == null) return true;
        return materials.preferBladeAuthHeader() || materials.bladeSurface();
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        // Demoted: never return commercial defaults as silent mint/dashboard FACT.
        // Only surface a redacted presence signal when code_query harvests material.
        if (artifactPath == null) {
            return Optional.empty();
        }
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(artifactPath, "jwt", 8);
        if (result.jwtSecretMaterialFound()) {
            return Optional.of("HARVESTED_REDACTED(keyLen="
                    + result.mintSecret().map(String::length).orElse(0)
                    + ";provenance=" + result.preferredSignKeyProvenance() + ")");
        }
        return Optional.empty();
    }

    @Override
    public List<String> jwtSecretHintNotes() {
        List<String> notes = new ArrayList<>();
        for (AuthCodeQueryService.WellKnownKey key : AuthCodeQueryService.wellKnownBladeKeyHints()) {
            notes.add(key.alias() + "(keyLen=" + key.keyLen()
                    + ") HINT only — call code_query to extract; not FACT unless harvested");
        }
        return List.copyOf(notes);
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        // Library order for AI; DEFAULT_SECRET_HS256 only mintable after harvest.
        return List.of(
                AuthBypassTechnique.MISSING_AUTH,
                AuthBypassTechnique.EMPTY_BEARER,
                AuthBypassTechnique.DEFAULT_SECRET_HS256,
                AuthBypassTechnique.ALG_NONE);
    }

    private static boolean containsAny(String value, Set<String> signals) {
        String lower = value == null ? "" : value.toLowerCase(Locale.ROOT);
        for (String signal : signals) {
            if (lower.contains(signal)) return true;
        }
        return false;
    }
}
