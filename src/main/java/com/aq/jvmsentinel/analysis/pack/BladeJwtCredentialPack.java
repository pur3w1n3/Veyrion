package com.aq.jvmsentinel.analysis.pack;

import com.aq.jvmsentinel.analysis.framework.SpringBladeAdapter;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Optional thin AnalysisPack for SpringBlade-like JWT credential experiment shapes
 * (non-destructive templates). Not a first-class product path — same SPI as any pack.
 *
 * <p>Does not mint or expose commercial defaults as FACT. Well-known aliases live on
 * {@link SpringBladeAdapter}; minting requires artifact harvest through {@code code_query}.
 */
public final class BladeJwtCredentialPack implements AnalysisPack {
    /**
     * @deprecated Detection dictionary owned by {@link SpringBladeAdapter}; pack keeps
     * the alias for fixture alignment only.
     */
    @Deprecated
    public static final String DEFAULT_SECRET = SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY;

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
        if (artifactPath == null) {
            return Optional.empty();
        }
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(artifactPath, "jwt", 8);
        if (result.jwtSecretMaterialFound()) {
            return Optional.of("HARVESTED_REDACTED(keyLen="
                    + result.mintSecret().map(String::length).orElse(0) + ")");
        }
        return Optional.empty();
    }

    @Override
    public List<ExperimentPlan> experimentTemplates(String entrypointRef, IdentityTrack track) {
        return List.of(new ExperimentPlan(
                "plan-multi-header-jwt-" + track.name().toLowerCase(Locale.ROOT),
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
