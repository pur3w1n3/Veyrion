package com.aq.jvmsentinel.instrumentation.mock;

import com.aq.jvmsentinel.instrumentation.AgentRuntime;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.util.Map;
import java.util.jar.JarFile;

/** Enables in-sandbox JDBC driver registration and loopback Redis stub. */
public final class DependencyMockBootstrap {
    private static volatile LoopbackRedisStub redisStub;
    private static volatile LoopbackMysqlStub mysqlStub;

    private DependencyMockBootstrap() {
    }

    public static void install(Instrumentation instrumentation, boolean dependencyMock,
                               String worldPackDependencyMode) {
        boolean observeFail = "OBSERVE_FAIL".equalsIgnoreCase(worldPackDependencyMode);
        // OBSERVE_FAIL still needs the mock JDBC driver so Statement.execute* can record SQL
        // text (H3 / PathTrace) and then fail closed. Skip Redis/MySQL success stubs that
        // would continue business past unavailable real dependencies.
        if (observeFail) {
            try {
                JarFile agentJar = agentJarFile();
                if (agentJar != null) {
                    instrumentation.appendToSystemClassLoaderSearch(agentJar);
                }
                VeyrionMockDriver.register();
                QuartzInstanceIdFailOpen.install(instrumentation);
                AgentRuntime.recordJdbc(DependencyMockBootstrap.class.getName(), "install",
                        Map.of("captureMode", "DEPENDENCY_MOCK",
                                "dependencyMode", "OBSERVE_FAIL",
                                "provenance", "SERVER_FIXED_POLICY",
                                "outcome", "OBSERVE_FAIL",
                                "jdbc", "veyrion-mock"));
            } catch (Exception failure) {
                AgentRuntime.recordJdbc(DependencyMockBootstrap.class.getName(), "installFailed",
                        Map.of("captureMode", "DEPENDENCY_MOCK",
                                "dependencyMode", "OBSERVE_FAIL",
                                "error", failure.getClass().getSimpleName()));
            }
            return;
        }
        if (!dependencyMock) return;
        try {
            JarFile agentJar = agentJarFile();
            if (agentJar != null) {
                instrumentation.appendToSystemClassLoaderSearch(agentJar);
            }
            VeyrionMockDriver.register();
            QuartzInstanceIdFailOpen.install(instrumentation);
            if (redisStub == null) {
                redisStub = LoopbackRedisStub.start(6379);
            }
            if (mysqlStub == null) {
                mysqlStub = LoopbackMysqlStub.start(3306);
            }
            AgentRuntime.recordJdbc(DependencyMockBootstrap.class.getName(), "install",
                    Map.of("captureMode", "DEPENDENCY_MOCK",
                            "dependencyMode", "MOCK",
                            "provenance", "RULE_GENERATED",
                            "jdbc", "veyrion-mock",
                            "redisPort", Integer.toString(redisStub.port()),
                            "mysqlPort", Integer.toString(mysqlStub.port())));
        } catch (Exception failure) {
            AgentRuntime.recordJdbc(DependencyMockBootstrap.class.getName(), "installFailed",
                    Map.of("captureMode", "DEPENDENCY_MOCK",
                            "error", failure.getClass().getSimpleName()));
        }
    }

    private static JarFile agentJarFile() throws IOException {
        String path = DependencyMockBootstrap.class.getProtectionDomain().getCodeSource() == null
                ? null
                : DependencyMockBootstrap.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        if (path == null || path.isBlank()) return null;
        if (path.startsWith("/") && path.length() > 2 && path.charAt(2) == ':') {
            path = path.substring(1);
        }
        path = java.net.URLDecoder.decode(path, java.nio.charset.StandardCharsets.UTF_8);
        java.io.File file = new java.io.File(path);
        if (!file.isFile()) return null;
        return new JarFile(file);
    }
}
