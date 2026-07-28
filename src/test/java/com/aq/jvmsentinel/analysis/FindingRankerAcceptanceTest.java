package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-20: static-first finding ranking demotes UNREACHED / MOCK dynamic noise.
 */
public final class FindingRankerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        staticHighBeforeUnreached();
        mockDynamicDemotedVersusStaticSink();
        System.out.println("FindingRankerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void staticHighBeforeUnreached() {
        ApiDtos.FindingDto unreached = finding("f-unreached", "UNREACHED", "high", 0.9, "other");
        ApiDtos.FindingDto staticSql = finding("f-static-sql", "STATIC_INFERRED", "high", 0.7, "SQL injection");
        List<ApiDtos.FindingDto> ranked = FindingRanker.rank(List.of(unreached, staticSql));
        check(ranked.size() == 2, "two findings ranked");
        check("f-static-sql".equals(ranked.get(0).findingId()), "static SQL finding ranks first");
        check("f-unreached".equals(ranked.get(1).findingId()), "UNREACHED demoted");
    }

    private static void mockDynamicDemotedVersusStaticSink() {
        ApiDtos.FindingDto mockDynamic = finding("f-mock-dyn", "DYNAMIC_SUSPECTED", "medium", 0.8, "noise");
        ApiDtos.FindingDto staticCmd = finding("f-static-cmd", "STATIC_INFERRED", "critical", 0.6, "COMMAND exec");
        List<ApiDtos.FindingDto> ranked = FindingRanker.rank(List.of(mockDynamic, staticCmd));
        check("f-static-cmd".equals(ranked.get(0).findingId()),
                "critical static command finding outranks MOCK DYNAMIC_SUSPECTED");
    }

    private static ApiDtos.FindingDto finding(String id, String status, String severity,
                                              double confidence, String sink) {
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "project-rank", "a".repeat(64), "scan-rank",
                id, "title-" + id, severity, status, "entry-1", "GET /x",
                "sink-" + id, sink, "none", List.of(), List.of("ev-" + id), 1, confidence, "MOCK");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
