package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Default Spring MVC adapter for non-Blade surfaces. */
public final class SpringMvcAdapter implements FrameworkAdapter {
    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "admin", "upload", "deploy", "token", "exec", "oauth", "sql", "jndi", "ssrf", "deserial");
    // Do not include bare "controller" — nearly every Spring MVC class matches and starves probe budget.
    private static final Set<String> CLASS_SIGNALS = Set.of(
            "admin", "upload", "deploy", "oauth");

    @Override
    public String id() {
        return "spring-mvc";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> routes) {
        return true;
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
        return false;
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        return Optional.empty();
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        return List.of(AuthBypassTechnique.MISSING_AUTH, AuthBypassTechnique.ALG_NONE);
    }
}
