package com.aq.jvmsentinel.domain.runtime;

import java.util.Objects;

/** Fail-closed guard: RuntimeAdapter never accepts untrusted command/image/mount/UID/network/budget. */
public final class RuntimeAdapterGuard {
    private RuntimeAdapterGuard() {
    }

    public static RuntimeRunProfile requireServerFixed(
            RuntimeRunProfile profile,
            RuntimeAdapterOverrideAttempt attempt
    ) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(attempt, "attempt");
        if (attempt.hasAnyOverride()) {
            throw new SecurityException("RUNTIME_OVERRIDE_REJECTED:" + attempt.overrideFields());
        }
        return profile;
    }
}
