package com.aq.jvmsentinel.agent;

import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Context-path 日志识别 + 探针 wire URL 前缀。
 */
public final class HttpContextPathDetectorAcceptanceTest {
    private HttpContextPathDetectorAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        detectsCatalinaAbbrevLogLine();
        detectsSpringBootAndPropertyLines();
        joinDoesNotDoublePrefix();
        probeUsesContextPathPrefixFromLog();
        System.out.println("HttpContextPathDetectorAcceptanceTest: PASS");
    }

    private static void detectsCatalinaAbbrevLogLine() {
        String log = "17:01:58.536 logback [main] INFO  o.a.c.c.C.[.[.[/xxl-job-admin] "
                + "- Initializing Spring embedded WebApplicationContext\n";
        check("/xxl-job-admin".equals(HttpContextPathDetector.detectFromText(log)),
                "Catalina abbrev logger must yield /xxl-job-admin, got="
                        + HttpContextPathDetector.detectFromText(log));
        String full = "org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/admin] "
                + "Initializing Spring embedded WebApplicationContext";
        check("/admin".equals(HttpContextPathDetector.detectFromText(full)),
                "Catalina full logger must yield /admin");
    }

    private static void detectsSpringBootAndPropertyLines() {
        check("/app".equals(HttpContextPathDetector.detectFromText(
                        "Tomcat started on port(s): 8080 (http) with context path '/app'")),
                "Spring Boot context path line");
        check("/xxl-job-admin".equals(HttpContextPathDetector.detectFromText(
                        "server.servlet.context-path=/xxl-job-admin")),
                "server.servlet.context-path property");
        check("".equals(HttpContextPathDetector.detectFromText(
                        "Tomcat started on port(s): 8080 (http) with context path '/'")),
                "root context path is empty prefix");
    }

    private static void joinDoesNotDoublePrefix() {
        check("/xxl-job-admin/chartInfo".equals(
                        HttpContextPathDetector.join("/xxl-job-admin", "/chartInfo")),
                "join chartInfo");
        check("/xxl-job-admin".equals(
                        HttpContextPathDetector.join("/xxl-job-admin", "/")),
                "join root route");
        check("/xxl-job-admin/chartInfo".equals(
                        HttpContextPathDetector.join("/xxl-job-admin", "/xxl-job-admin/chartInfo")),
                "already-prefixed route must not double");
        check("/xxl-job-admin/login?user=a".equals(
                        HttpContextPathDetector.joinRequestTarget(
                                "/xxl-job-admin", "/login?user=a")),
                "query preserved on wire target");
    }

    private static void probeUsesContextPathPrefixFromLog() throws Exception {
        Path traceDir = Files.createTempDirectory("veyrion-ctx-path-");
        try {
            Files.writeString(traceDir.resolve("application.log"),
                    "17:01:58.536 logback [main] INFO  o.a.c.c.C.[.[.[/xxl-job-admin] "
                            + "- Initializing Spring embedded WebApplicationContext\n",
                    StandardCharsets.UTF_8);
            AtomicReference<String> seenTarget = new AtomicReference<>("");
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/xxl-job-admin/chartInfo", exchange -> {
                seenTarget.set(exchange.getRequestURI().getRawPath());
                byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.createContext("/", exchange -> {
                seenTarget.set(exchange.getRequestURI().getRawPath());
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
            });
            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);
            server.start();
            int port = server.getAddress().getPort();
            Path plan = traceDir.resolve("probe-plan.txt");
            Files.writeString(plan, "GET\t/chartInfo\t\tUNAUTH\n", StandardCharsets.UTF_8);
            String previousTrace = System.getProperty("veyrion.sandbox.traceDir");
            String previousCtx = System.getProperty("veyrion.loopbackProbe.contextPath");
            try {
                System.setProperty("veyrion.sandbox.traceDir", traceDir.toString());
                System.clearProperty("veyrion.loopbackProbe.contextPath");
                int code = LoopbackHttpProbe.runBatch(plan, port);
                check(code == 0, "batch probe should succeed with context-path prefix, code=" + code);
                check("/xxl-job-admin/chartInfo".equals(seenTarget.get()),
                        "wire URI must include context-path, seen=" + seenTarget.get());
                String events = Files.readString(traceDir.resolve("probe-events.jsonl"),
                        StandardCharsets.UTF_8);
                check(events.contains("\"route\":\"/chartInfo\""),
                        "event route stays logical MVC mapping");
                check(events.contains("\"requestTarget\":\"/chartInfo\""),
                        "event requestTarget stays logical for coverage");
                check(events.contains("\"wireRequestTarget\":\"/xxl-job-admin/chartInfo\""),
                        "event records wireRequestTarget with prefix");
                check(events.contains("\"contextPath\":\"/xxl-job-admin\""),
                        "event records detected contextPath");
                check("/xxl-job-admin".equals(
                                HttpContextPathDetector.readContextPathFile(traceDir)),
                        "http-context-path.txt persisted for retained sandbox");
            } finally {
                if (previousTrace == null) System.clearProperty("veyrion.sandbox.traceDir");
                else System.setProperty("veyrion.sandbox.traceDir", previousTrace);
                if (previousCtx == null) System.clearProperty("veyrion.loopbackProbe.contextPath");
                else System.setProperty("veyrion.loopbackProbe.contextPath", previousCtx);
                server.stop(0);
                pool.shutdownNow();
            }
        } finally {
            deleteRecursively(traceDir);
        }
    }

    private static void deleteRecursively(Path root) throws Exception {
        if (root == null || !Files.exists(root)) return;
        try (var walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                        }
                    });
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
