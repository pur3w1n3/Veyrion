package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** facts_search kind=PATH_TRACE rejects client policy override fields. */
public final class PathTraceQueryDenialAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        store.createProject("local", "deny", now, "test");
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, "local", "digest-deny", "scan-deny",
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");
        com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource source =
                new com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource(store, "scan-deny");
        com.aq.jvmsentinel.ai.tool.ToolExecutionContext.Scope scope =
                new com.aq.jvmsentinel.ai.tool.ToolExecutionContext.Scope("local", "local");
        for (String forbidden : List.of("forcedReachability=true", "command=evil", "budget=9999")) {
            boolean denied = false;
            try {
                source.searchFacts(scope, "PATH_TRACE", forbidden, 8);
            } catch (SecurityException expected) {
                denied = true;
            }
            check(denied, "denied query: " + forbidden);
        }
        System.out.println("PathTraceQueryDenialAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}
