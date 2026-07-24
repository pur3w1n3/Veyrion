package com.aq.jvmsentinel.worker;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

/** Main-style acceptance checks for the execute-one Fixture Worker launcher. */
public final class FixtureWorkerMainAcceptanceTest {
    private static final String WORKER_SECRET = "worker-secret-do-not-print";
    private static final String API_SECRET = "api-secret-do-not-print";
    private static final String EXECD_SECRET = "execd-secret-do-not-print";
    private static final String DIGEST = "a".repeat(64);
    private static final String FEATURES = String.join(",",
            "lifecycle-v1", "execd-command-v1", "network-deny-v1",
            "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1");

    private FixtureWorkerMainAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Map<String, String> valid = validEnvironment("http://127.0.0.1:9/internal/worker/v1/");
        FixtureWorkerMain.Configuration configuration =
                FixtureWorkerMain.Configuration.load(valid, new Properties());
        String description = configuration.toString();
        assertNoSecrets(description, "configuration description");

        Properties override = new Properties();
        override.setProperty("veyrion.worker.id", "property-worker");
        FixtureWorkerMain.Configuration.load(valid, override);

        Map<String, String> missingWorkerToken = copy(valid);
        missingWorkerToken.remove("VEYRION_WORKER_TOKEN");
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(missingWorkerToken, new Properties()),
                "missing Worker secret");
        Map<String, String> missingApiKey = copy(valid);
        missingApiKey.remove("VEYRION_OPENSANDBOX_API_KEY");
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(missingApiKey, new Properties()),
                "missing lifecycle secret");
        Map<String, String> missingExecdToken = copy(valid);
        missingExecdToken.remove("VEYRION_OPENSANDBOX_EXECD_TOKEN");
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(missingExecdToken, new Properties()),
                "missing Execd secret");

        Map<String, String> wrongCapability = copy(valid);
        wrongCapability.put("VEYRION_OPENSANDBOX_ATTESTATION_CAPABILITY", "HARDENED_GVISOR");
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(wrongCapability, new Properties()),
                "wrong capability");
        Map<String, String> missingFeature = copy(valid);
        missingFeature.put("VEYRION_OPENSANDBOX_ATTESTATION_FEATURES",
                FEATURES.replace(",read-only-rootfs-v1", ""));
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(missingFeature, new Properties()),
                "missing isolation feature");
        Map<String, String> wrongRuntime = copy(valid);
        wrongRuntime.put("VEYRION_OPENSANDBOX_ATTESTATION_RUNTIME", "runsc");
        expect(FixtureWorkerMain.ConfigurationException.class,
                () -> FixtureWorkerMain.Configuration.load(wrongRuntime, new Properties()),
                "wrong runtime");

        FixtureTaskExecutor.ExecutionResult result = new FixtureTaskExecutor.ExecutionResult(
                new TaskScope("project-1", DIGEST, "scan-1", "task-1"),
                2, "b".repeat(64), TaskLifecycle.COMPLETED);
        String summary = FixtureWorkerMain.summaryJson(result);
        check(summary.equals("{\"traceChunks\":2,\"headDigest\":\"" + "b".repeat(64)
                        + "\",\"taskId\":\"task-1\",\"lifecycle\":\"COMPLETED\"}")
                        || summary.contains("\"taskId\":\"task-1\"")
                        && summary.contains("\"lifecycle\":\"COMPLETED\"")
                        && summary.contains("\"traceChunks\":2")
                        && summary.contains("\"headDigest\":\"" + "b".repeat(64) + "\""),
                "structured success summary");
        assertNoSecrets(summary, "success summary");

        assertRedirectRejected();
        System.out.println("FixtureWorkerMainAcceptanceTest: PASS");
    }

    private static void assertRedirectRejected() throws Exception {
        AtomicInteger redirectedRequests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/worker/v1/tasks/task-1", exchange -> {
            exchange.getResponseHeaders().set("Location", "/redirected");
            respond(exchange, 302, "");
        });
        server.createContext("/redirected", exchange -> {
            redirectedRequests.incrementAndGet();
            respond(exchange, 200, "{}");
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort()
                    + "/internal/worker/v1/";
            FixtureWorkerMain.Configuration configuration =
                    FixtureWorkerMain.Configuration.load(validEnvironment(base), new Properties());
            ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
            RuntimeException failure = expect(RuntimeException.class,
                    () -> FixtureWorkerMain.executeOne(configuration,
                            new PrintStream(outputBytes, true, StandardCharsets.UTF_8)),
                    "Control Plane redirect");
            check(redirectedRequests.get() == 0, "redirect target must not be requested");
            check(outputBytes.size() == 0, "failed execution must not emit success output");
            assertNoSecrets(failure.toString(), "redirect exception");
        } finally {
            server.stop(0);
        }
    }

    private static Map<String, String> validEnvironment(String controlBaseUri) {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("VEYRION_CONTROL_INTERNAL_BASE_URI", controlBaseUri);
        values.put("VEYRION_WORKER_TOKEN", WORKER_SECRET);
        values.put("VEYRION_PROJECT_ID", "project-1");
        values.put("VEYRION_ARTIFACT_DIGEST", DIGEST);
        values.put("VEYRION_SCAN_ID", "scan-1");
        values.put("VEYRION_TASK_ID", "task-1");
        values.put("VEYRION_WORKER_ID", "worker-1");
        values.put("VEYRION_OPENSANDBOX_LIFECYCLE_URI", "http://127.0.0.1:9/v1/");
        values.put("VEYRION_OPENSANDBOX_API_KEY", API_SECRET);
        values.put("VEYRION_OPENSANDBOX_EXECD_TOKEN", EXECD_SECRET);
        values.put("VEYRION_OPENSANDBOX_ATTESTATION_RUNTIME", "runc");
        values.put("VEYRION_OPENSANDBOX_ATTESTATION_CAPABILITY", "FIXTURE_RUNC");
        values.put("VEYRION_OPENSANDBOX_ATTESTATION_FEATURES", FEATURES);
        values.put("VEYRION_OPENSANDBOX_ATTESTATION_PROTOCOL", "0.1.0");
        return values;
    }

    private static Map<String, String> copy(Map<String, String> source) {
        return new LinkedHashMap<>(source);
    }

    private static void assertNoSecrets(String value, String message) {
        check(!value.contains(WORKER_SECRET), message + " leaks Worker token");
        check(!value.contains(API_SECRET), message + " leaks API key");
        check(!value.contains(EXECD_SECRET), message + " leaks Execd token");
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable runnable,
                                                   String message) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return type.cast(actual);
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
