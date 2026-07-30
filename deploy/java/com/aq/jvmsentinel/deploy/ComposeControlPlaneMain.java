package com.aq.jvmsentinel.deploy;

import com.aq.jvmsentinel.control.ControlPlaneServer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/**
 * Container-oriented Control Plane launcher.
 *
 * <p>Unlike {@code ControlPlaneMain}, this binds to an explicit host (default
 * {@code 0.0.0.0}) so Docker port publishing works. Intended for local Compose
 * deployments only; not a production hardened service.</p>
 */
public final class ComposeControlPlaneMain {
    private ComposeControlPlaneMain() { }

    public static void main(String[] args) throws Exception {
        Path root = null;
        Path database = null;
        String bind = "0.0.0.0";
        int port = 18080;
        String token = ControlPlaneServer.DEFAULT_TOKEN;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--root" -> {
                    if (++i >= args.length) usage();
                    root = Path.of(args[i]);
                }
                case "--database" -> {
                    if (++i >= args.length) usage();
                    database = Path.of(args[i]);
                }
                case "--bind" -> {
                    if (++i >= args.length) usage();
                    bind = args[i];
                }
                case "--port" -> {
                    if (++i >= args.length) usage();
                    try {
                        port = Integer.parseInt(args[i]);
                    } catch (NumberFormatException invalid) {
                        usage();
                    }
                    if (port < 0 || port > 65535) usage();
                }
                case "--token" -> {
                    if (++i >= args.length) usage();
                    token = args[i];
                }
                case "--help", "-h" -> usage();
                default -> usage();
            }
        }
        if (root == null || !Files.isDirectory(root)) usage();
        if (bind == null || bind.isBlank()) usage();
        if (database == null) {
            database = root.resolve(".veyrion").resolve("control-plane.db");
        }
        Files.createDirectories(database.getParent());
        try (ControlPlaneServer server =
                     new ControlPlaneServer(bind, port, root, token, database).start()) {
            System.out.println("Control Plane listening at " + server.baseUri());
            System.out.println("Compose launcher: dynamic TRUSTED_DOCKER worker is not started here.");
            System.out.println("Sandbox unavailable => DYNAMIC_DISABLED; never falls back to host execution.");
            new CountDownLatch(1).await();
        }
    }

    private static void usage() {
        System.err.println("usage: ComposeControlPlaneMain --root <allowed-artifact-directory> "
                + "[--database <path>] [--bind <host>] [--port <0-65535>] [--token <local-token>]");
        System.exit(2);
    }
}
