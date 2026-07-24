package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.fixture.TrustedFixtureCatalog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/** Small local launcher for the dependency-free Control Plane. */
public final class ControlPlaneMain {
    private ControlPlaneMain() { }

    public static void main(String[] args) throws Exception {
        Path root = null;
        Path database = null;
        int port = 0;
        String token = ControlPlaneServer.DEFAULT_TOKEN;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--root" -> {
                    if (++i >= args.length) usage();
                    root = Path.of(args[i]);
                }
                case "--port" -> {
                    if (++i >= args.length) usage();
                    try { port = Integer.parseInt(args[i]); } catch (NumberFormatException invalid) { usage(); }
                    if (port < 0 || port > 65535) usage();
                }
                case "--token" -> {
                    if (++i >= args.length) usage();
                    token = args[i];
                }
                case "--database" -> {
                    if (++i >= args.length) usage();
                    database = Path.of(args[i]);
                }
                case "--help", "-h" -> usage();
                default -> usage();
            }
        }
        if (root == null || !Files.isDirectory(root)) usage();
        if (database == null) database = root.resolve(".veyrion").resolve("control-plane.db");
        TrustedFixtureCatalog fixtureCatalog = TrustedFixtureCatalog.fromEnvironment(System.getenv());
        try (ControlPlaneServer server =
                     new ControlPlaneServer("127.0.0.1", port, root, token, fixtureCatalog, database).start()) {
            System.out.println("Control Plane listening at " + server.baseUri());
            System.out.println("Mutation token is configured locally; imported artifacts are metadata-only in this MVP.");
            new CountDownLatch(1).await();
        }
    }

    private static void usage() {
        System.err.println("usage: ControlPlaneMain --root <allowed-artifact-directory> "
                + "[--database <path-under-root>] [--port <0-65535>] [--token <local-token>]");
        System.exit(2);
    }
}
