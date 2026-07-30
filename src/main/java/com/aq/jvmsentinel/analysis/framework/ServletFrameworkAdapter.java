package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Servlet/Filter 面的第二 FrameworkAdapter 骨架（P2 SCAFFOLDING）。
 *
 * <p>Contributes route/class HINT signals only. Does not elevate verification status,
 * 发明 FACT，或自行启用 WAR dynamic execution。
 */
public final class ServletFrameworkAdapter implements FrameworkAdapter {
    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "servlet", "filter", "/servlet/", "doGet", "doPost");
    private static final Set<String> CLASS_SIGNALS = Set.of(
            "HttpServlet", "Filter", "javax.servlet", "jakarta.servlet");
    private static final Set<String> AUTH_CLASS_PATHS = Set.of(
            "javax/servlet/Filter",
            "jakarta/servlet/Filter",
            "javax/servlet/http/HttpServlet",
            "jakarta/servlet/http/HttpServlet",
            "org/apache/shiro",
            "CookieRememberMeManager",
            "RememberMeManager");

    @Override
    public String id() {
        return "servlet";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> routes) {
        if (routes != null) {
            for (String route : routes) {
                if (containsAny(route, ROUTE_SIGNALS)) {
                    return true;
                }
            }
        }
        if (artifactPath != null) {
            String name = fileName(artifactPath);
            if (name.endsWith(".war") || name.contains("servlet")) {
                return true;
            }
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
                "HINT: ServletFrameworkAdapter matches Servlet/Filter surfaces; "
                        + "auth Filter/HttpServlet evidence requires code_query (not FACT).");
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        return List.of(AuthBypassTechnique.MISSING_AUTH);
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
