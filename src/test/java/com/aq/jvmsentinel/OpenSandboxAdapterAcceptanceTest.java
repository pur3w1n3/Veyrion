package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.*;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local HTTP acceptance checks for the fail-closed OpenSandbox protocol adapter. */
public final class OpenSandboxAdapterAcceptanceTest {
    private static final String API_KEY = "lifecycle-secret-key";
    private static final String EXECD_TOKEN = "execd-secret-token";
    private static final ResourceBudget BUDGET =
            new ResourceBudget(120, 10_000, 256 * 1024 * 1024L, 64 * 1024 * 1024L, 8 * 1024 * 1024L);

    public static void main(String[] args) throws Exception {
        MockOpenSandbox mock = new MockOpenSandbox();
        mock.start();
        try {
            OpenSandboxClient client = client(mock, Duration.ofSeconds(2));
            SandboxRequest request = request("fixture:latest", true, WorkerCapability.FIXTURE_RUNC);
            SandboxHandle created = client.create(request);
            check(created.id().equals("sandbox-1"), "create handle");
            check(client.get(created.id()).status().state() == SandboxStatus.State.RUNNING, "get status");
            check(client.pause(created.id()).status().state() == SandboxStatus.State.PAUSING, "pause status");
            check(client.resume(created.id()).status().state() == SandboxStatus.State.RESUMING, "resume status");
            CommandResult result = client.command(created.id(), new CommandRequest(
                    "java -version", "/workspace", Duration.ofSeconds(3), 1000, 1000));
            check(result.exitCode() == 0 && result.stdout().equals("ok"), "command result");
            expect(OpenSandboxException.class, () -> client.command("sandbox-unknown", new CommandRequest(
                    "id", "/workspace", Duration.ofSeconds(1), 1000, 1000)), "unknown sandbox binding");
            client.delete(created.id());

            expect(OpenSandboxException.class, () -> client.create(
                    request("error:latest", true, WorkerCapability.FIXTURE_RUNC)), "HTTP error");
            expect(OpenSandboxException.class, () -> client.create(
                    request("malformed:latest", true, WorkerCapability.FIXTURE_RUNC)), "malformed JSON");
            OpenSandboxException downgrade = expect(OpenSandboxException.class, () -> client.create(
                    request("downgrade:latest", false, WorkerCapability.HARDENED_GVISOR)), "capability downgrade");
            check(downgrade.code().equals("CAPABILITY_DOWNGRADE"), "downgrade error code");
            expect(OpenSandboxException.class, () -> client(mock, Duration.ofMillis(100)).create(
                    request("timeout:latest", true, WorkerCapability.FIXTURE_RUNC)), "timeout");
            SandboxHandle crossOrigin = client.create(
                    request("cross-origin:latest", true, WorkerCapability.FIXTURE_RUNC));
            expect(OpenSandboxException.class, () -> client.command(crossOrigin.id(), new CommandRequest(
                    "id", "/workspace", Duration.ofSeconds(1), 1000, 1000)), "cross-origin endpoint");
            SandboxHandle misbound = client.create(
                    request("misbound:latest", true, WorkerCapability.FIXTURE_RUNC));
            expect(OpenSandboxException.class, () -> client.command(misbound.id(), new CommandRequest(
                    "id", "/workspace", Duration.ofSeconds(1), 1000, 1000)), "sandbox endpoint binding");
            SandboxHandle headerOverride = client.create(
                    request("header-override:latest", true, WorkerCapability.FIXTURE_RUNC));
            expect(OpenSandboxException.class, () -> client.command(headerOverride.id(), new CommandRequest(
                    "id", "/workspace", Duration.ofSeconds(1), 1000, 1000)), "authentication header override");

            expect(IllegalArgumentException.class, () -> new CommandRequest(
                    "id", "/workspace", Duration.ofSeconds(1), 0, 1000), "root UID");
            expect(IllegalArgumentException.class, () -> request(
                    "external:latest", false, WorkerCapability.FIXTURE_RUNC), "external runc");

            mock.assertObserved();
            System.out.println("OpenSandboxAdapterAcceptanceTest: PASS");
        } finally {
            mock.close();
        }
    }

    private static OpenSandboxClient client(MockOpenSandbox mock, Duration timeout) {
        URI root = URI.create("http://127.0.0.1:" + mock.port() + "/");
        return new OpenSandboxClient(new OpenSandboxConfig(
                root.resolve("v1/"), API_KEY, EXECD_TOKEN, timeout, "0.1.0",
                new RuntimeAttestation("0.1.0", WorkerCapability.FIXTURE_RUNC, "runc",
                        true, true, true, Set.of(
                        "lifecycle-v1", "execd-command-v1", "network-deny-v1",
                        "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1"))));
    }

    private static SandboxRequest request(String image, boolean fixtureOnly, WorkerCapability capability) {
        return new SandboxRequest(image, List.of("sleep", "infinity"), 60, BUDGET, fixtureOnly, capability);
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable runnable, String message)
            throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return type.cast(actual);
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable { void run() throws Exception; }

    private static final class MockOpenSandbox implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor;
        private final List<Observed> observed = new ArrayList<>();

        private MockOpenSandbox() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            executor = Executors.newCachedThreadPool();
            server.setExecutor(executor);
        }

        void start() { server.start(); }
        int port() { return server.getAddress().getPort(); }

        private synchronized void handle(HttpExchange exchange) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            observed.add(new Observed(exchange.getRequestMethod(), exchange.getRequestURI().getPath(),
                    exchange.getRequestHeaders().getFirst("OPEN-SANDBOX-API-KEY"),
                    exchange.getRequestHeaders().getFirst("X-EXECD-ACCESS-TOKEN"),
                    exchange.getRequestHeaders().getFirst("X-OpenSandbox-Endpoint-Token"), body));
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/v1/sandboxes") && exchange.getRequestMethod().equals("POST")) {
                String image = image(body);
                if (image.equals("error:latest")) {
                    respond(exchange, 503, "application/json", "{\"code\":\"UNAVAILABLE\",\"message\":\"no\"}");
                } else if (image.equals("malformed:latest")) {
                    respond(exchange, 202, "application/json", "{broken");
                } else if (image.equals("timeout:latest")) {
                    try {
                        Thread.sleep(400);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    }
                    respond(exchange, 202, "application/json", handleJson("sandbox-timeout", "Running"));
                } else if (image.equals("downgrade:latest")) {
                    respond(exchange, 202, "application/json", handleJson("sandbox-down", "Running"));
                } else if (image.equals("cross-origin:latest")) {
                    respond(exchange, 202, "application/json", handleJson("sandbox-cross", "Running"));
                } else if (image.equals("misbound:latest")) {
                    respond(exchange, 202, "application/json", handleJson("sandbox-misbound", "Running"));
                } else if (image.equals("header-override:latest")) {
                    respond(exchange, 202, "application/json", handleJson("sandbox-header", "Running"));
                } else {
                    respond(exchange, 202, "application/json", handleJson("sandbox-1", "Running"));
                }
                return;
            }
            if (path.equals("/v1/sandboxes/sandbox-1") && exchange.getRequestMethod().equals("GET")) {
                respond(exchange, 200, "application/json", handleJson("sandbox-1", "Running"));
            } else if (path.equals("/v1/sandboxes/sandbox-1/pause")) {
                respond(exchange, 202, "application/json", handleJson("sandbox-1", "Pausing"));
            } else if (path.equals("/v1/sandboxes/sandbox-1/resume")) {
                respond(exchange, 202, "application/json", handleJson("sandbox-1", "Resuming"));
            } else if (path.equals("/v1/sandboxes/sandbox-1") && exchange.getRequestMethod().equals("DELETE")) {
                respond(exchange, 204, "application/json", "");
            } else if (path.equals("/v1/sandboxes/sandbox-1/endpoints/44772")) {
                respond(exchange, 200, "application/json", endpointJson(
                        origin() + "/proxy/sandboxes/sandbox-1/port/44772",
                        Map.of("X-OpenSandbox-Endpoint-Token", "proxy-token")));
            } else if (path.equals("/v1/sandboxes/sandbox-cross/endpoints/44772")) {
                respond(exchange, 200, "application/json", endpointJson(
                        "http://example.invalid/sandboxes/sandbox-cross/port/44772", Map.of()));
            } else if (path.equals("/v1/sandboxes/sandbox-misbound/endpoints/44772")) {
                respond(exchange, 200, "application/json", endpointJson(
                        origin() + "/proxy/sandboxes/sandbox-other/port/44772", Map.of()));
            } else if (path.equals("/v1/sandboxes/sandbox-header/endpoints/44772")) {
                respond(exchange, 200, "application/json", endpointJson(
                        origin() + "/proxy/sandboxes/sandbox-header/port/44772",
                        Map.of("X-EXECD-ACCESS-TOKEN", "attacker-token")));
            } else if (path.equals("/proxy/sandboxes/sandbox-1/port/44772/command")) {
                respond(exchange, 200, "application/json",
                        "{\"id\":\"command-1\",\"stdout\":\"ok\",\"stderr\":\"\",\"exit_code\":0}");
            } else {
                respond(exchange, 404, "application/json", "{\"code\":\"NOT_FOUND\",\"message\":\"missing\"}");
            }
        }

        @SuppressWarnings("unchecked")
        private static String image(String body) {
            return (String) ((Map<String, Object>) JsonCodec.parseObject(body).get("image")).get("uri");
        }

        private String origin() {
            return "http://127.0.0.1:" + port();
        }

        private static String handleJson(String id, String state) {
            return JsonCodec.stringify(Map.of(
                    "id", id,
                    "status", Map.of("state", state)));
        }

        private static String endpointJson(String endpoint, Map<String, String> headers) {
            return JsonCodec.stringify(Map.of("endpoint", endpoint, "headers", headers));
        }

        private static void respond(HttpExchange exchange, int status, String contentType, String body)
                throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(status, status == 204 ? -1 : bytes.length);
            if (status != 204) exchange.getResponseBody().write(bytes);
            exchange.close();
        }

        synchronized void assertObserved() {
            check(observed.stream().anyMatch(value -> value.path().equals("/v1/sandboxes/sandbox-1/pause")),
                    "pause URI");
            check(observed.stream().anyMatch(value -> value.path().equals("/v1/sandboxes/sandbox-1/resume")),
                    "resume URI");
            check(observed.stream().anyMatch(value -> value.method().equals("DELETE")
                    && value.path().equals("/v1/sandboxes/sandbox-1")), "delete URI");
            check(observed.stream().anyMatch(value ->
                    value.path().equals("/v1/sandboxes/sandbox-1/endpoints/44772")), "execd endpoint discovery");
            check(observed.stream().noneMatch(value ->
                    value.path().contains("sandbox-unknown")), "unknown sandbox must not trigger discovery");
            check(observed.stream().noneMatch(value ->
                    value.path().equals("/proxy/sandboxes/sandbox-header/port/44772/command")),
                    "forbidden header must block command");
            for (Observed value : observed) {
                check(!value.body().contains(API_KEY) && !value.body().contains(EXECD_TOKEN), "secret in body");
                if (value.path().startsWith("/v1/")) {
                    check(API_KEY.equals(value.lifecycleKey()), "lifecycle auth header");
                    check(value.execdToken() == null, "execd token leaked to lifecycle");
                }
                if (value.path().startsWith("/proxy/")) {
                    check(EXECD_TOKEN.equals(value.execdToken()), "execd auth header");
                    check(value.lifecycleKey() == null, "lifecycle key leaked to execd");
                    check("proxy-token".equals(value.proxyToken()), "safe proxy header");
                    Map<String, Object> command = JsonCodec.parseObject(value.body());
                    check(((Number) command.get("uid")).intValue() == 1000, "non-root uid");
                    check(((Number) command.get("gid")).intValue() == 1000, "non-root gid");
                    check(!command.containsKey("envs"), "command environment prohibited");
                }
            }
            Observed create = observed.stream().filter(value -> value.path().equals("/v1/sandboxes")).findFirst()
                    .orElseThrow();
            Map<String, Object> request = JsonCodec.parseObject(create.body());
            check(!request.containsKey("env") && !request.containsKey("volumes")
                    && !request.containsKey("credentialProxy"), "unsafe create fields prohibited");
            @SuppressWarnings("unchecked")
            Map<String, Object> network = (Map<String, Object>) request.get("networkPolicy");
            check(network.get("defaultAction").equals("deny"), "network must default deny");
            check(request.containsKey("resourceLimits") && request.containsKey("extensions"), "resource budget");
        }

        @Override public void close() {
            server.stop(0);
            executor.shutdownNow();
        }
    }

    private record Observed(String method, String path, String lifecycleKey, String execdToken,
                            String proxyToken, String body) { }
}
