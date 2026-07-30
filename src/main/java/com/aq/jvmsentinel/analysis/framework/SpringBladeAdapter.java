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
 * 可选薄 SpringBlade / BladeX adapter — 贡献 route/class signal 与
 * 次要 header HINT（{@code Blade-Auth}），同其他 FrameworkAdapter。
 * 非 first-class 产品路径；control plane / identity / AUTH 保持 JVM-generic。
 *
 * <p>{@link #suggestJwtSecret} never returns commercial defaults for silent minting.
 * Well-known alias 仅 HINT，经 {@link #jwtSecretHintNotes()} / {@link #wellKnownSecretHints()}；
 * AI 须调用 {@code code_query} 从 authorized artifact harvest 材料。
 */
public final class SpringBladeAdapter implements FrameworkAdapter {
    /**
     * 历史 Blade/JwtProperties commercial default — 仅 adapter detection dictionary。
     * 除非从 artifact harvest，否则不作 FACT 或 mint。
     */
    public static final String WELL_KNOWN_COMMERCIAL_SIGN_KEY =
            "bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject";
    /** Legacy all-zero placeholder — adapter detection dictionary only. */
    public static final String WELL_KNOWN_LEGACY_ZERO_KEY =
            "00000000000000000000000000000000";

    private static final Set<String> ROUTE_SIGNALS = Set.of(
            "blade-", "bladex", "/blade-", "oauth", "token");
    private static final Set<String> CLASS_SIGNALS = Set.of(
            "blade", "bladex", "org.springblade");
    private static final Set<String> AUTH_CLASS_PATHS = Set.of(
            "org/springblade/core/secure",
            "org/springblade/core/jwt",
            "org/springblade/modules/auth",
            "BladeTokenEndPoint",
            "BladeSecure");

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
    public boolean preferSecondaryAuthHeader(SyntheticIdentityService.MaterialBundle materials) {
        // Framework HINT：本 adapter 面通常双 channel 次要 auth header。
        if (materials == null) return true;
        return materials.preferSecondaryAuthHeader() || materials.multiHeaderAuthSurface();
    }

    @Override
    public String secondaryAuthHeaderName() {
        return "Blade-Auth";
    }

    @Override
    public List<AuthCodeQueryService.WellKnownKey> wellKnownSecretHints() {
        return List.of(
                new AuthCodeQueryService.WellKnownKey(
                        "WELL_KNOWN_ADAPTER_SPRINGBLADE_COMMERCIAL", WELL_KNOWN_COMMERCIAL_SIGN_KEY),
                new AuthCodeQueryService.WellKnownKey(
                        "WELL_KNOWN_ADAPTER_SPRINGBLADE_LEGACY_ZERO", WELL_KNOWN_LEGACY_ZERO_KEY));
    }

    @Override
    public Set<String> authClassPathSignals() {
        return AUTH_CLASS_PATHS;
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
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
        for (AuthCodeQueryService.WellKnownKey key : wellKnownSecretHints()) {
            notes.add(key.alias() + "(keyLen=" + key.keyLen()
                    + ") HINT only — call code_query to extract; not FACT unless harvested");
        }
        notes.add("secondaryAuthHeaderName=" + secondaryAuthHeaderName()
                + " (wire field bladeAuthHeader is a deprecated alias)");
        return List.copyOf(notes);
    }

    @Override
    public List<AuthBypassTechnique> defaultBypassTechniques() {
        // AI 的 library 顺序；DEFAULT_SECRET_HS256 仅 harvest 后可 mint。
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
