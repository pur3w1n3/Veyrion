package com.aq.jvmsentinel.instrumentation;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

final class ObservationTransformer implements ClassFileTransformer {
    private static final String AGENT_PACKAGE = "com/aq/jvmsentinel/instrumentation/";

    private final String classPrefix;
    private final ThreadLocal<Boolean> recording = ThreadLocal.withInitial(() -> false);

    ObservationTransformer(String classPrefix) {
        this.classPrefix = classPrefix;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null || !observed(className) || recording.get()) return null;
        recording.set(true);
        try {
            AgentRuntime.recordClassLoad(className.replace('/', '.'));
        } catch (Throwable ignored) {
            // Observation must not alter the loaded class or grant any capability.
        } finally {
            recording.set(false);
        }
        return null;
    }

    private boolean observed(String className) {
        if (!classPrefix.isEmpty()) return className.startsWith(classPrefix);
        return !className.startsWith("java/")
                && !className.startsWith("javax/")
                && !className.startsWith("jdk/")
                && !className.startsWith("sun/")
                && !className.startsWith(AGENT_PACKAGE);
    }
}
