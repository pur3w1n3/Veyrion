package com.aq.jvmsentinel.agent;

import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/** Dual-phase loopback flood: fast pass + capped slow retry for BUSINESS_TIMEOUT. */
public final class LoopbackHttpProbeAcceptanceTest {
    private LoopbackHttpProbeAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        classifyTaxonomyPreserved();
        siblingPortFileIsValidated();
        slowRetryPrioritizesUnauthAndCaps();
        dualPhaseRecoversSlowAuthChallenge();
        authAndBladeChannelsAreIndependent();
        System.out.println("LoopbackHttpProbeAcceptanceTest: PASS");
    }

    private static void siblingPortFileIsValidated() throws Exception {
        Path directory = Files.createTempDirectory("veyrion-probe-port-");
        Path plan = directory.resolve("probe-plan.txt");
        Files.writeString(plan, "GET\t/\t\tUNAUTH\n", StandardCharsets.UTF_8);
        Path portFile = directory.resolve("http-port.txt");

        Files.writeString(portFile, "54321\n", StandardCharsets.US_ASCII);
        check(LoopbackHttpProbe.readSiblingHttpPort(plan) == 54321,
                "single-argument batch mode reads the fixed sibling HTTP port");

        Path detachedPlan = Files.createTempDirectory("veyrion-detached-plan-")
                .resolve("probe-plan.txt");
        Files.writeString(detachedPlan, "GET\t/\t\tUNAUTH\n", StandardCharsets.UTF_8);
        String previousTraceDirectory = System.getProperty("veyrion.sandbox.traceDir");
        try {
            System.setProperty("veyrion.sandbox.traceDir", directory.toString());
            check(LoopbackHttpProbe.readConfiguredHttpPort(detachedPlan) == 54321,
                    "configured trace directory supplies the HTTP port independently of plan parsing");
        } finally {
            if (previousTraceDirectory == null) System.clearProperty("veyrion.sandbox.traceDir");
            else System.setProperty("veyrion.sandbox.traceDir", previousTraceDirectory);
        }

        String previous = System.getProperty("veyrion.loopbackProbe.port");
        try {
            System.setProperty("veyrion.loopbackProbe.port", "23456");
            check(LoopbackHttpProbe.readConfiguredHttpPort(plan) == 23456,
                    "fixed JVM property takes precedence over the sibling port file");
            for (String invalid : List.of("0", "65536", "not-a-port")) {
                System.setProperty("veyrion.loopbackProbe.port", invalid);
                try {
                    LoopbackHttpProbe.readConfiguredHttpPort(plan);
                    throw new AssertionError("invalid configured HTTP port must be rejected: " + invalid);
                } catch (IllegalArgumentException expected) {
                    // Expected fail-closed validation.
                }
            }
        } finally {
            if (previous == null) System.clearProperty("veyrion.loopbackProbe.port");
            else System.setProperty("veyrion.loopbackProbe.port", previous);
        }

        for (String invalid : List.of("", "0", "65536", "not-a-port")) {
            Files.writeString(portFile, invalid, StandardCharsets.US_ASCII);
            try {
                LoopbackHttpProbe.readSiblingHttpPort(plan);
                throw new AssertionError("invalid sibling HTTP port must be rejected: " + invalid);
            } catch (IllegalArgumentException expected) {
                // Expected fail-closed validation.
            }
        }
        Files.deleteIfExists(portFile);
        try {
            LoopbackHttpProbe.readSiblingHttpPort(plan);
            throw new AssertionError("missing sibling HTTP port must be rejected");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed validation.
        }
    }

    /** Authorization-only and Blade-Auth-only plans must not copy into the other channel. */
    private static void authAndBladeChannelsAreIndependent() {
        String authOnly = LoopbackHttpProbe.buildRequestHeaders(
                "GET", "/admin", 0, "tok-auth", "");
        check(authOnly.contains("Authorization: bearer tok-auth\r\n"),
                "auth-only plan must set Authorization");
        check(!authOnly.toLowerCase().contains("blade-auth:"),
                "auth-only plan must not invent Blade-Auth");

        String bladeOnly = LoopbackHttpProbe.buildRequestHeaders(
                "GET", "/admin", 0, "", "tok-blade");
        check(bladeOnly.contains("Blade-Auth: tok-blade\r\n"),
                "blade-only plan must set Blade-Auth");
        check(!bladeOnly.toLowerCase().contains("authorization:"),
                "blade-only plan must not invent Authorization");

        String both = LoopbackHttpProbe.buildRequestHeaders(
                "GET", "/admin", 0, "tok-a", "tok-b");
        check(both.contains("Authorization: bearer tok-a\r\n")
                        && both.contains("Blade-Auth: tok-b\r\n"),
                "when both channels are set they remain distinct");
        check(!both.contains("Blade-Auth: tok-a"),
                "authHeader must not be copied into Blade-Auth");
    }

    private static void classifyTaxonomyPreserved() {
        check(LoopbackHttpProbe.classifyOutcome(-1, "SocketTimeoutException")
                        .equals("BUSINESS_TIMEOUT"),
                "SocketTimeout must stay BUSINESS_TIMEOUT");
        check(LoopbackHttpProbe.classifyOutcome(-1, "ConnectException").equals("COLD_START"),
                "ConnectException must stay COLD_START");
        check(LoopbackHttpProbe.classifyOutcome(401, "").equals("AUTH_CHALLENGE"),
                "401 must stay AUTH_CHALLENGE");
        check(LoopbackHttpProbe.classifyOutcome(403, "").equals("AUTH_CHALLENGE"),
                "403 must stay AUTH_CHALLENGE");
        check(Boolean.TRUE.equals(LoopbackHttpProbe.classifyEntryHit(200)),
                "2xx entryHit true");
        check(Boolean.TRUE.equals(LoopbackHttpProbe.classifyEntryHit(401)),
                "401 entryHit true");
        check(Boolean.FALSE.equals(LoopbackHttpProbe.classifyEntryHit(404)),
                "404 entryHit false");
        check(LoopbackHttpProbe.classifyEntryHit(-1) == null,
                "transport failure leaves entryHit absent");
        check(Boolean.FALSE.equals(LoopbackHttpProbe.classifyParameterBound(404)),
                "404 parameterBound false from probe");
        check(LoopbackHttpProbe.classifyParameterBound(200) == null,
                "probe must not invent parameterBound=true on 200");
        check(LoopbackHttpProbe.trackRetryRank("UNAUTH") < LoopbackHttpProbe.trackRetryRank("USER"),
                "UNAUTH must rank ahead of USER for slow retry");
    }

    private static void slowRetryPrioritizesUnauthAndCaps() {
        List<LoopbackHttpProbe.ProbeAttempt> timedOut = new ArrayList<>();
        for (int i = 1; i <= 40; i++) {
            timedOut.add(timeoutAttempt("ADMIN", i));
        }
        for (int i = 41; i <= 100; i++) {
            timedOut.add(timeoutAttempt("UNAUTH", i));
        }
        for (int i = 101; i <= 120; i++) {
            timedOut.add(timeoutAttempt("USER", i));
        }
        List<LoopbackHttpProbe.ProbeAttempt> selected =
                LoopbackHttpProbe.selectSlowRetryTargets(timedOut, 64);
        check(selected.size() == 64, "slow retry must honor cap");
        long unauth = selected.stream().filter(a -> "UNAUTH".equals(a.target.track)).count();
        long user = selected.stream().filter(a -> "USER".equals(a.target.track)).count();
        long admin = selected.stream().filter(a -> "ADMIN".equals(a.target.track)).count();
        check(unauth == 60, "all UNAUTH timeouts should be taken before other tracks");
        check(user == 4 && admin == 0, "USER fills remainder before ADMIN");
        List<LoopbackHttpProbe.ProbeAttempt> tiny =
                LoopbackHttpProbe.selectSlowRetryTargets(timedOut.subList(0, 3), 128);
        check(tiny.size() == 3, "cap must not invent retries");
    }

    private static void dualPhaseRecoversSlowAuthChallenge() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/fast", exchange -> {
            byte[] body = "denied".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/slow", exchange -> {
            try {
                Thread.sleep(1_200);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            byte[] body = "denied-slow".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/hang", exchange -> {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        ExecutorService serverPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "loopback-probe-fixture");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(serverPool);
        server.start();
        int port = server.getAddress().getPort();
        Path work = Path.of("target", "loopback-probe-acceptance").toAbsolutePath().normalize();
        if (Files.exists(work)) {
            try (var walk = Files.walk(work)) {
                walk.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception ignored) {
                    }
                });
            }
        }
        Files.createDirectories(work);
        Path trace = work.resolve("trace");
        Files.createDirectories(trace);
        Path plan = work.resolve("plan.txt");
        Files.writeString(plan, String.join("\n",
                "GET\t/fast\t\tUNAUTH",
                "GET\t/slow\t\tUNAUTH",
                "GET\t/hang\t\tUNAUTH",
                "GET\t/slow\t\tUSER"), StandardCharsets.UTF_8);

        String previous = System.getProperty("veyrion.sandbox.traceDir");
        System.setProperty("veyrion.sandbox.traceDir", trace.toString());
        System.setProperty("veyrion.loopbackProbe.threads", "4");
        try {
            LoopbackHttpProbe.main(new String[]{
                    "--batch", plan.toString(), Integer.toString(port)
            });
            Path events = trace.resolve("probe-events.jsonl");
            check(Files.isRegularFile(events), "probe-events.jsonl must exist");
            List<String> lines = Files.readAllLines(events, StandardCharsets.UTF_8);
            check(lines.size() == 4, "exactly one final HTTP event per target, got " + lines.size());
            String joined = lines.stream().collect(Collectors.joining("\n"));
            check(joined.contains("\"route\":\"/fast\"") && joined.contains("AUTH_CHALLENGE"),
                    "fast path must observe AUTH_CHALLENGE");
            check(countOutcome(lines, "/slow", "AUTH_CHALLENGE") >= 1,
                    "slow path must recover AUTH_CHALLENGE via 2000ms wave-2");
            check(countOutcome(lines, "/hang", "BUSINESS_TIMEOUT") == 1,
                    "hang path may remain BUSINESS_TIMEOUT after slow retry");
            // /slow USER also times out in wave-1; with only 2 UNAUTH timeouts ahead of it
            // in selection (slow+hang), USER slow should also be eligible under cap 128.
            check(countOutcome(lines, "/slow", "AUTH_CHALLENGE")
                            + countOutcome(lines, "/slow", "BUSINESS_TIMEOUT") == 2,
                    "both /slow tracks must emit exactly one final outcome each");
        } finally {
            if (previous == null) System.clearProperty("veyrion.sandbox.traceDir");
            else System.setProperty("veyrion.sandbox.traceDir", previous);
            System.clearProperty("veyrion.loopbackProbe.threads");
            server.stop(0);
            serverPool.shutdownNow();
            serverPool.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    private static int countOutcome(List<String> lines, String route, String outcome) {
        int count = 0;
        for (String line : lines) {
            if (line.contains("\"route\":\"" + route + "\"")
                    && line.contains("\"outcomeClass\":\"" + outcome + "\"")) {
                count++;
            }
        }
        return count;
    }

    private static LoopbackHttpProbe.ProbeAttempt timeoutAttempt(String track, int ordinal) {
        LoopbackHttpProbe.ProbeTarget target = new LoopbackHttpProbe.ProbeTarget(
                "GET", "/r" + ordinal, "", track, "", ordinal);
        return new LoopbackHttpProbe.ProbeAttempt(target, -1, "SocketTimeoutException",
                "/r" + ordinal, 800, 800);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
