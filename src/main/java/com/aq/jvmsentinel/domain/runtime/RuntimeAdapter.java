package com.aq.jvmsentinel.domain.runtime;

import java.util.Set;

/**
 * Out-of-process RuntimeAdapter port (P1-07 skeleton).
 *
 * <p>Adapters describe capability; they never accept model/frontend-supplied command, image,
 * mount, UID, network or budget overrides. Those fields come only from {@link RuntimeRunProfile}.
 */
public interface RuntimeAdapter {
    String runtimeKind();

    String runtimeVersion();

    Set<String> declaredCapabilities();

    /**
     * Bind a server-fixed profile. Implementations must call
     * {@link RuntimeAdapterGuard#requireServerFixed(RuntimeRunProfile, RuntimeAdapterOverrideAttempt)}
     * before any launch.
     */
    RuntimeRunProfile bindProfile(RuntimeRunProfile profile);
}
