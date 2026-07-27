package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** SpringBlade / BladeX surface heuristics previously hard-coded in ControlPlaneServer. */
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
        if (materials == null) return false;
        return materials.preferBladeAuthHeader() || materials.bladeSurface();
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        return Optional.of("bladexisapowerfulmicroservicearchitectureupgradedversion");
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        return List.of(
                AuthBypassTechnique.DEFAULT_SECRET_HS256,
                AuthBypassTechnique.ALG_NONE,
                AuthBypassTechnique.MISSING_AUTH);
    }

    private static boolean containsAny(String value, Set<String> signals) {
        String lower = value == null ? "" : value.toLowerCase(Locale.ROOT);
        for (String signal : signals) {
            if (lower.contains(signal)) return true;
        }
        return false;
    }
}
