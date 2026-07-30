package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 默认 Spring MVC adapter — 始终作为 JVM-generic baseline 匹配。
 * 不 prefer 次要 auth header；HS256 mint 需 artifact harvest。
 */
public final class SpringMvcAdapter implements FrameworkAdapter {
    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "admin", "upload", "deploy", "token", "exec", "oauth", "sql", "jndi", "ssrf", "deserial");
    // 勿包含裸 "controller" — 几乎每 Spring MVC class 都匹配并耗尽 probe budget。
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
    public boolean preferSecondaryAuthHeader(SyntheticIdentityService.MaterialBundle materials) {
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
