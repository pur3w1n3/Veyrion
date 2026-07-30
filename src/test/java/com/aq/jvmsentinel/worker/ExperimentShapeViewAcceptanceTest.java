package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.List;
import java.util.Map;

/** P2-04：一条 PathRun → 供人类与 AI 使用的规范化调试形状。 */
public final class ExperimentShapeViewAcceptanceTest {
    public static void main(String[] args) {
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-shape-1", "scan-1", "entry:e1", "UNAUTH",
                "attempt-0", null, "GET", "application/json",
                "GET /api/users?q=1", "COMPLETED", 200, true, true,
                List.of(new ApiDtos.SqlEventDto(
                        "SELECT 1", "p", "READ", true, false, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-1"), "MOCK", "");
        ExperimentShapeView.Shape shape = ExperimentShapeView.fromPathRun(run);
        check("pathrun-shape-1".equals(shape.pathRunId()), "pathRunId");
        check(shape.httpLine().contains("/api/users"), "httpLine from requestSummary");
        check(Boolean.TRUE.equals(shape.entryHit()) && Boolean.TRUE.equals(shape.parameterBound()),
                "bind flags");
        check(shape.sqlTexts().contains("SELECT 1"), "sqlTexts");
        check("MOCK".equals(shape.dependencyMode()), "dependencyMode MOCK");
        check(!"VERIFIED".equals(shape.verificationStatus()), "never VERIFIED");

        Map<String, Object> map = ExperimentShapeView.toMap(shape);
        check("SELECT 1".equals(((List<?>) map.get("sqlTexts")).get(0)), "map sqlTexts");

        try {
            new ExperimentShapeView.Shape(
                    "x", "entry:e1", "UNAUTH", "GET /x", 200, true, true, List.of(),
                    "COMPLETED", "COMPLETED", "MOCK", "VERIFIED", List.of());
            throw new AssertionError("VERIFIED shape must be rejected");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains("VERIFIED"), "reject VERIFIED");
        }

        System.out.println("ExperimentShapeViewAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
