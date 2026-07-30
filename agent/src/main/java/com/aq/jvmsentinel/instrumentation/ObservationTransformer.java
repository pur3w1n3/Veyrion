package com.aq.jvmsentinel.instrumentation;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

final class ObservationTransformer implements ClassFileTransformer {
    private final AgentConfig config;
    private final ThreadLocal<Boolean> recording = ThreadLocal.withInitial(() -> false);

    ObservationTransformer(AgentConfig config) {
        this.config = config;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null || !observed(className) || recording.get()) return null;
        recording.set(true);
        try {
            AgentRuntime.recordClassLoad(className.replace('/', '.'));
        } catch (Throwable ignored) {
            // Observation 不得改变已加载 class 或授予任何 capability。
        } finally {
            recording.set(false);
        }
        return null;
    }

    private boolean observed(String className) {
        return config.includes(className);
    }
}
