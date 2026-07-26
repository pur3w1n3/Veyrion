package com.aq.jvmsentinel.model;

import java.util.Locale;
import java.util.Optional;

/**
 * Optional known technique labels. AI may author arbitrary PoC material; these ids
 * are only fallbacks when the model names a known technique without supplying headers.
 */
public enum AuthBypassTechnique {
    MISSING_AUTH(IdentityTrack.UNAUTH),
    EMPTY_BEARER(IdentityTrack.BYPASS_CANDIDATE),
    DEFAULT_SECRET_HS256(IdentityTrack.BYPASS_CANDIDATE),
    ALG_NONE(IdentityTrack.BYPASS_CANDIDATE),
    ROLE_CONFUSION(IdentityTrack.USER),
    LOGOUT_TOKEN(IdentityTrack.BYPASS_CANDIDATE),
    CUSTOM_POC(IdentityTrack.BYPASS_CANDIDATE);

    private final IdentityTrack defaultTrack;

    AuthBypassTechnique(IdentityTrack defaultTrack) {
        this.defaultTrack = defaultTrack;
    }

    public IdentityTrack defaultTrack() {
        return defaultTrack;
    }

    public static Optional<AuthBypassTechnique> tryParse(String value) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            return Optional.of(AuthBypassTechnique.valueOf(value.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }
}
