package com.aq.jvmsentinel.ai.memory;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Verifies same-scan shared memory snapshot shape for AI + GUI.
 * Uses in-memory store (no SQLite Jackson encode path).
 */
public final class ScanMemoryBuilderAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-mem", "Memory", now, "local-admin");
        String digest = "a".repeat(64);
        String scanId = "scan-memory-test";
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, scanId, "entry-1",
                "HTTP", "GET", "/api/item", "example.ItemController", "example",
                List.of(), List.of(), "STATIC_INFERRED", 0.8, 0, List.of());
        var sink = new ApiDtos.SinkDto(1, project.projectId(), digest, scanId, "sink-1",
                "EXPRESSION", "demo.execute", "BYTECODE", "PRESENT", 0.5, List.of());
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, scanId,
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of(), List.of(entry), List.of(), List.of(sink), List.of(), List.of());
        // In-memory path: put scan directly via saveScan without artifact persistence.
        try {
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()),
                    "local-admin");
        } catch (RuntimeException missingArtifact) {
            // Some store builds require an artifact; fall back to reflection-free map build
            // by injecting via requireScan after a minimal register is unavailable in-memory.
            throw missingArtifact;
        }

        Map<String, Object> full = ScanMemoryBuilder.build(store, scanId, List.of(), Map.of(
                "PRE_ANALYSIS", "前置建模摘要示例"));
        check(Integer.valueOf(1).equals(full.get("schemaVersion")), "schemaVersion=1");
        check(full.containsKey("facts"), "has facts");
        check(full.containsKey("work"), "has work");
        check(full.containsKey("toolsCatalog"), "has toolsCatalog");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> tools = (List<Map<String, Object>>) full.get("toolsCatalog");
        check(tools.stream().anyMatch(t -> "scan_memory_get".equals(t.get("name"))),
                "catalog includes scan_memory_get");
        check(tools.stream().anyMatch(t -> "sandbox_probe".equals(t.get("name"))),
                "catalog includes sandbox_probe");

        Map<String, Object> index = ScanMemoryBuilder.indexOnly(full);
        check(index.containsKey("howToDeepen"), "index has deepen hints");
        Map<String, Object> toolsSection = ScanMemoryBuilder.section(full, "TOOLS_CATALOG");
        check(toolsSection.containsKey("toolsCatalog"), "TOOLS_CATALOG section");
        System.out.println("ScanMemoryBuilderAcceptanceTest passed ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
    }
}
