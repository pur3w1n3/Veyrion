package com.aq.jvmsentinel.domain.runtime;

import java.util.Set;

/**
 * 进程外 RuntimeAdapter port（P1-07 骨架）。
 *
 * <p>Adapters describe capability; they never accept model/frontend-supplied command, image,
 * mount、UID、network 或 budget override。这些 field 仅来自 {@link RuntimeRunProfile}。
 */
public interface RuntimeAdapter {
    String runtimeKind();

    String runtimeVersion();

    Set<String> declaredCapabilities();

    /**
     * 绑定服务端固定 profile。实现必须调用
     * {@link RuntimeAdapterGuard#requireServerFixed(RuntimeRunProfile, RuntimeAdapterOverrideAttempt)}
     * 于任何 launch 之前。
     */
    RuntimeRunProfile bindProfile(RuntimeRunProfile profile);
}
