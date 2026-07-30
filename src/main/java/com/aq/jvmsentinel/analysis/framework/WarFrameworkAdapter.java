package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.RunProfile;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * WAR 向 FrameworkAdapter 骨架（P2 SCAFFOLDING）。
 *
 * <p>Matches {@code .war} / {@code WEB-INF} surfaces and exposes neutral HINT notes.
 * Dynamic execution 保持 {@link RunProfile#MODE_WAR_DYNAMIC_DISABLED} 直至未来
 * 审计过的 embedded-container profile 落地 — 本 adapter 永不授予 host execution。
 */
public final class WarFrameworkAdapter implements FrameworkAdapter {
    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "web-inf", "/web.xml", "jsp", "servlet");
    private static final Set<String> CLASS_SIGNALS = Set.of(
            "WEB-INF", "web.xml", "ServletContextListener");
    private static final Set<String> AUTH_CLASS_PATHS = Set.of(
            "WEB-INF/web.xml",
            "WEB-INF/classes",
            "WEB-INF/lib");

    @Override
    public String id() {
        return "war";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> routes) {
        if (artifactPath != null) {
            String name = fileName(artifactPath);
            if (name.endsWith(".war")) {
                return true;
            }
        }
        if (routes != null) {
            for (String route : routes) {
                if (containsAny(route, ROUTE_SIGNALS)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * WAR 的中性 dynamic-policy fact：profile 存在不启用 host execution。
     */
    public static String dynamicPolicyFact(boolean profileProvided) {
        RunProfile profile = RunProfile.forArtifact(ArtifactType.WAR, false, profileProvided);
        return profile.failureMode();
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
    public Set<String> authClassPathSignals() {
        return AUTH_CLASS_PATHS;
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        return Optional.empty();
    }

    @Override
    public List<String> jwtSecretHintNotes() {
        return List.of(
                "HINT: WarFrameworkAdapter matches WAR/WEB-INF surfaces; "
                        + "dynamic mode stays WAR_DYNAMIC_DISABLED (not FACT elevation).");
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        return List.of(AuthBypassTechnique.MISSING_AUTH, AuthBypassTechnique.ALG_NONE);
    }

    private static boolean containsAny(String value, Set<String> signals) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        for (String signal : signals) {
            if (lower.contains(signal.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String fileName(Path artifactPath) {
        Path name = artifactPath.getFileName();
        return name == null ? "" : name.toString().toLowerCase(Locale.ROOT);
    }
}
