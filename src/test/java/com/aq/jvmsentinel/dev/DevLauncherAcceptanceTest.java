package com.aq.jvmsentinel.dev;

import com.aq.jvmsentinel.control.ControlPlaneServer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Dependency-free checks for the local two-process development launcher. */
public final class DevLauncherAcceptanceTest {
    private DevLauncherAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("veyrion-dev-launcher-");
        Path frontend = Files.createDirectory(workspace.resolve("frontend"));
        Files.writeString(frontend.resolve("package.json"), "{}");
        Path vite = Files.createDirectories(frontend.resolve("node_modules/vite/bin"))
                .resolve("vite.js");
        Files.writeString(vite, "// fixture");

        DevLauncherMain.Configuration config = DevLauncherMain.Configuration.parse(new String[] {
                "--workspace", workspace.toString(),
                "--backend-port", "18080",
                "--frontend-port", "15173",
                "--node", "trusted-node"
        }, workspace);
        check(config.artifactRoot().equals(workspace.resolve("samples")),
                "default artifact directory stays in workspace");
        check(DevLauncherMain.frontendCommand(config).equals(List.of(
                        "trusted-node", vite.toString(), "--host", "127.0.0.1",
                        "--port", "15173", "--strictPort")),
                "frontend command launches Vite directly and loopback-only");

        reject(() -> DevLauncherMain.Configuration.parse(new String[] {
                "--workspace", workspace.toString(), "--artifacts", workspace.resolve("..").toString()
        }, workspace), "artifact directory escape");
        reject(() -> DevLauncherMain.Configuration.parse(new String[] {
                "--workspace", workspace.toString(), "--backend-port", "5173",
                "--frontend-port", "5173"
        }, workspace), "port collision");
        reject(() -> DevLauncherMain.Configuration.parse(new String[] {
                "--workspace", workspace.toString(), "--unknown", "value"
        }, workspace), "unknown option");

        Path artifacts = Files.createDirectory(workspace.resolve("artifacts"));
        Path database = artifacts.resolve(".veyrion").resolve("control-plane.db");
        DevLauncherMain.syncFrontendEnv(config, java.net.URI.create("http://127.0.0.1:18080/api/v1"),
                "launcher-test-token");
        String env = Files.readString(frontend.resolve(".env.local"));
        check(env.contains("VITE_API_BASE_URL=http://127.0.0.1:18080/api/v1"),
                "frontend env carries the control-plane base URL");
        check(env.contains("VITE_API_TOKEN=launcher-test-token"),
                "frontend env carries the mutation token");
        check(!env.contains("VITE_PROJECT_ID="),
                "frontend env does not force a default workspace id");

        try (ControlPlaneServer server =
                     new ControlPlaneServer(artifacts, 0, "first-launch-token", database).start()) {
            check(server.store().authenticateOperator("first-launch-token") != null,
                    "bootstrap token authenticates operators");
            check(server.store().projects().isEmpty(),
                    "launcher does not bootstrap a default development project");
        }
        try (ControlPlaneServer restarted =
                     new ControlPlaneServer(artifacts, 0, "second-launch-token", database).start()) {
            check(restarted.store().authenticateOperator("second-launch-token") != null,
                    "new process token rotates the persistent bootstrap credential");
            check(restarted.store().authenticateOperator("first-launch-token") == null,
                    "prior process token is revoked on restart");
        }

        System.out.println("DevLauncherAcceptanceTest: PASS");
    }

    private static void reject(ThrowingRunnable action, String message) throws Exception {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected rejection: " + message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
