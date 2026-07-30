package com.aq.jvmsentinel.instrumentation;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 校验 EventWriter：单 correlation 软分片 + 全局耗尽后 per-correlation 续写。
 */
public final class EventWriterBudgetFairShareAcceptanceTest {
    private EventWriterBudgetFairShareAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path work = Path.of("target", "event-writer-fair-share").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);

        String previousDir = System.getProperty(AgentConfig.TRACE_DIR_PROPERTY);
        String previousAuth = System.getProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY);
        Path authorized = work.resolve("authorized");
        Files.createDirectory(authorized);
        System.setProperty(AgentConfig.TRACE_DIR_PROPERTY, authorized.toString());
        System.setProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY, "true");
        try {
            verifySoftCapYieldsToSibling(authorized);
            verifyPostBudgetAfterGlobalStop(work.resolve("post-budget"));
            check(EventWriter.SOFT_CAP_EVENTS_PER_CORRELATION == 2_500,
                    "soft cap must match control-plane EVENTS_PER_PROBE");
            check(EventWriter.POST_BUDGET_CORRELATION_CAP == 512,
                    "post-budget correlation cap must cover max probe plan");
            check(EventWriter.POST_BUDGET_EVENTS_PER_CORRELATION == 128,
                    "post-budget per-correlation floor must remain strengthened");
        } finally {
            restoreProperty(AgentConfig.TRACE_DIR_PROPERTY, previousDir);
            restoreProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY, previousAuth);
        }
        System.out.println("EventWriterBudgetFairShareAcceptanceTest: PASS");
    }

    private static void verifySoftCapYieldsToSibling(Path authorized) throws Exception {
        AgentConfig config = AgentConfig.parse("maxEvents=8000,maxBytes=1048576");
        try (EventWriter writer = new EventWriter(config)) {
            int noisyAccepted = 0;
            for (int i = 0; i < EventWriter.SOFT_CAP_EVENTS_PER_CORRELATION + 200; i++) {
                if (writer.writeInstrumented("HTTP", "a.Noisy", "hop",
                        detail("corr-noisy", "METHOD_HOP"))) {
                    noisyAccepted++;
                }
            }
            check(noisyAccepted == EventWriter.SOFT_CAP_EVENTS_PER_CORRELATION,
                    "noisy correlation must stop at soft cap; accepted=" + noisyAccepted);

            int siblingAccepted = 0;
            for (int i = 0; i < 40; i++) {
                if (writer.writeInstrumented("HTTP", "b.Sibling", "hop",
                        detail("corr-sibling", "METHOD_HOP"))) {
                    siblingAccepted++;
                }
            }
            check(siblingAccepted == 40,
                    "sibling correlation must still write after noisy soft-cap; accepted="
                            + siblingAccepted);
            check(!writer.isStopped(), "soft-cap alone must not stop the global writer");
        }

        List<String> lines = Files.readAllLines(authorized.resolve(AgentConfig.TRACE_FILE_NAME),
                StandardCharsets.UTF_8);
        long noisy = lines.stream().filter(l -> l.contains("corr-noisy")).count();
        long sibling = lines.stream().filter(l -> l.contains("corr-sibling")).count();
        check(noisy == EventWriter.SOFT_CAP_EVENTS_PER_CORRELATION,
                "trace noisy count mismatch: " + noisy);
        check(sibling == 40, "trace sibling count mismatch: " + sibling);
        check(lines.stream().noneMatch(l -> l.contains("TRACE_BUDGET_EXHAUSTED")),
                "soft-cap must not emit global TRACE_BUDGET_EXHAUSTED");
    }

    private static void verifyPostBudgetAfterGlobalStop(Path dir) throws Exception {
        Files.createDirectories(dir);
        System.setProperty(AgentConfig.TRACE_DIR_PROPERTY, dir.toString());
        AgentConfig config = AgentConfig.parse("maxEvents=3,maxBytes=1048576");
        try (EventWriter writer = new EventWriter(config)) {
            check(writer.writeInstrumented("HTTP", "c.Early", "a", detail("corr-a", "ENTRY_HIT")),
                    "first event");
            check(writer.writeInstrumented("HTTP", "c.Early", "b", detail("corr-a", "METHOD_HOP")),
                    "second event");
            check(writer.writeInstrumented("HTTP", "c.Early", "c", detail("corr-a", "METHOD_HOP")),
                    "third event reaches global maxEvents count");
            // 下一次非关键写入触发 TRACE_BUDGET_EXHAUSTED + per-correlation 续写。
            int post = 0;
            for (int i = 0; i < EventWriter.POST_BUDGET_EVENTS_PER_CORRELATION + 20; i++) {
                if (writer.writeInstrumented("HTTP", "d.Late", "hop",
                        detail("corr-late", "METHOD_HOP"))) {
                    post++;
                }
            }
            check(post == EventWriter.POST_BUDGET_EVENTS_PER_CORRELATION,
                    "late correlation must get post-budget hops; got " + post);
            check(writer.isStopped(), "writer must be stopped after global maxEvents");
            // Critical EFFECT still passes.
            check(writer.writeInstrumented("JDBC", "e.Sink", "execute",
                            Map.of("correlationId", "corr-late",
                                    "pathDebugKind", "EFFECT_TRIGGERED",
                                    "effectKind", "SQL_EXECUTE",
                                    "captureMode", "DEPENDENCY_MOCK",
                                    "sql", "select 1")),
                    "critical EFFECT must survive after post-budget exhaustion");
        }
        List<String> lines = Files.readAllLines(dir.resolve(AgentConfig.TRACE_FILE_NAME),
                StandardCharsets.UTF_8);
        check(lines.stream().anyMatch(l -> l.contains("TRACE_BUDGET_EXHAUSTED")),
                "global exhaustion must emit TRACE_BUDGET_EXHAUSTED");
        check(lines.stream().anyMatch(l -> l.contains("EFFECT_TRIGGERED")),
                "critical EFFECT must appear in trace");
    }

    private static Map<String, String> detail(String correlationId, String pathDebugKind) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("correlationId", correlationId);
        detail.put("pathDebugKind", pathDebugKind);
        return detail;
    }

    private static void restoreProperty(String key, String previous) {
        if (previous == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, previous);
        }
    }

    private static void deleteRecursively(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                            // best-effort cleanup
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
