package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 回归：AI 数据面静默丢数 / 错误分区 / 错误角色指引。
 * <ul>
 *   <li>facts_search kind=ANY 不得被 ENTRY 吃满 limit 后饿死 SINK/PATH_RUN</li>
 *   <li>scan_memory_get ROLE_SLICE + 非法 role 不得静默回落 INDEX</li>
 *   <li>scan memory sinkIndex 截断前优先高危类别；TRIAGE guidance 含 H4</li>
 * </ul>
 */
public final class AiDataSurfaceCorrectnessAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        factsSearchAnyDoesNotStarveLaterKinds();
        factsSearchPageMetaAndOffsetContinuation();
        factsSearchFindingKindAndBindingsTruncationMarker();
        pathTraceEventsWindowMarkedWhenTruncated();
        scanMemorySurvivesMissingAiJobStore();
        scanMemoryInvalidRoleRejected();
        sinkIndexPrefersHighImpactBeforeTruncate();
        triageGuidanceMentionsH4Effect();
        System.out.println("AiDataSurfaceCorrectnessAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void factsSearchAnyDoesNotStarveLaterKinds() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        store.createProject("local", "any-kind", now, "test");
        String digest = "d".repeat(64);
        String scanId = "scan-any-kind";
        List<ApiDtos.EntryDto> entries = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            entries.add(new ApiDtos.EntryDto(
                    ApiDtos.SCHEMA_VERSION, "local", digest, scanId, "entry-" + i,
                    "HTTP", "GET", "/api/e" + i, "demo.C", "demo",
                    List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of()));
        }
        ApiDtos.SinkDto sink = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "local", digest, scanId, "sink-cmd",
                "COMMAND", "Runtime.exec", "BYTECODE", ApiDtos.STATIC_INFERRED, 0.9, List.of());
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, "local", digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), entries, List.of(), List.of(sink), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");

        ApiDtos.PathRunDto pathRun = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-1", scanId, "entry:entry-0",
                "COVERAGE", "attempt-0", null, "GET", "application/json",
                "GET /api/e0", "HTTP_OBSERVED", 200,
                true, false, List.of(), "HTTP_OBSERVED", ApiDtos.DYNAMIC_SUSPECTED,
                List.of(), "MOCK", "");

        ControlPlaneToolDataSource source = new ControlPlaneToolDataSource(
                store, scanId,
                (projectId, artifactDigest, scopedScanId) -> List.of(),
                (scopedScanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs,
                        maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId) ->
                        java.util.Optional.empty(),
                (projectId, artifactDigest, scopedScanId) -> List.of(pathRun));

        ToolExecutionContext.Scope scope = new ToolExecutionContext.Scope("local", "local");
        List<FactRecord> any = source.searchFacts(scope, "ANY", "", 20);
        check(any.size() <= 20, "ANY respects limit");
        boolean hasSink = any.stream().anyMatch(r -> r.reference().startsWith("sink:"));
        boolean hasPathRun = any.stream().anyMatch(r -> r.reference().startsWith("pathrun:"));
        boolean hasEntry = any.stream().anyMatch(r -> r.reference().startsWith("entry:"));
        check(hasEntry, "ANY includes ENTRY samples");
        check(hasSink, "ANY must not starve SINK when ENTRY count > limit");
        check(hasPathRun, "ANY must not starve PATH_RUN when ENTRY count > limit");
    }

    /** facts_search 触顶时必须带 page meta，且 offset 可续取，不得静默当全集。 */
    private static void factsSearchPageMetaAndOffsetContinuation() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-page", "page", now, "test");
        String digest = "c".repeat(64);
        String scanId = "scan-page";
        List<ApiDtos.EntryDto> entries = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            entries.add(new ApiDtos.EntryDto(
                    ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId, "entry-p-" + i,
                    "HTTP", "GET", "/api/p" + i, "demo.C", "demo",
                    List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of()));
        }
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), entries, List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");
        AiToolRegistry registry = new AiToolRegistry(new ControlPlaneToolDataSource(store, scanId));
        ObjectNode args = JSON.createObjectNode();
        args.put("kind", "ENTRY");
        args.put("limit", 10);
        args.put("offset", 0);
        ToolResult page0 = registry.execute(
                new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, "page-0", "facts_search", args),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", project.projectId()),
                        "principal", "job-page", AgentRole.PRE_ANALYSIS,
                        new ToolExecutionContext.Budget(8, 65_536, 8, 65_536, Instant.now().plusSeconds(60))));
        check(page0.status() == ToolStatus.SUCCESS, "page0 SUCCESS");
        check(!page0.outputs().isEmpty()
                        && "facts_search:page".equals(page0.outputs().get(0).reference()),
                "first output is facts_search:page meta");
        var meta0 = page0.outputs().get(0).value();
        check(meta0.path("truncated").asBoolean(false), "page0 truncated=true when more remain");
        check(meta0.path("hasMore").asBoolean(false), "page0 hasMore=true");
        check(meta0.path("totalMatched").asInt() == 30, "totalMatched=30");
        check(page0.outputs().size() == 11, "meta + 10 entries");

        ObjectNode args1 = JSON.createObjectNode();
        args1.put("kind", "ENTRY");
        args1.put("limit", 10);
        args1.put("offset", 10);
        ToolResult page1 = registry.execute(
                new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, "page-1", "facts_search", args1),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", project.projectId()),
                        "principal", "job-page", AgentRole.PRE_ANALYSIS,
                        new ToolExecutionContext.Budget(8, 65_536, 8, 65_536, Instant.now().plusSeconds(60))));
        check(page1.status() == ToolStatus.SUCCESS, "page1 SUCCESS");
        boolean hasEntry10 = page1.outputs().stream()
                .anyMatch(o -> "entry:entry-p-10".equals(o.reference()));
        check(hasEntry10, "offset=10 returns entry-p-10");
    }

    /** FINDING kind + FindingBindings prompt 截断标记。 */
    private static void factsSearchFindingKindAndBindingsTruncationMarker() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-finding", "finding", now, "test");
        String digest = "d".repeat(64);
        String scanId = "scan-finding";
        List<ApiDtos.FindingDto> findings = new ArrayList<>();
        for (int i = 0; i < FindingBindings.MAX_BINDINGS + 3; i++) {
            findings.add(new ApiDtos.FindingDto(
                    ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "finding-" + i, "title-" + i, "MEDIUM", ApiDtos.STATIC_INFERRED,
                    "entry-x", "GET /x", "sink-x", "Sink.x", "none", List.of("none"),
                    List.of(), 0, 0.5, ApiDtos.MOCK));
        }
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), List.of(), findings, List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");
        ControlPlaneToolDataSource source = new ControlPlaneToolDataSource(store, scanId);
        List<FactRecord> page = source.searchFacts(
                new ToolExecutionContext.Scope("local", project.projectId()),
                "FINDING", "", 20);
        check(page.size() == 20, "FINDING kind returns findings");
        check(page.get(0).reference().startsWith("finding:"), "finding: reference");

        FindingBindings.AssembleResult assembled = FindingBindings.assembleDetailed(
                findings, List.of(), List.of(), Map.of(),
                com.aq.jvmsentinel.provider.AiOutputLanguage.ZH_CN);
        check(assembled.bindings().size() == findings.size(),
                "deliverable assembleDetailed keeps all findings (no hard cap)");
        check(!assembled.truncated(),
                "deliverable assembleDetailed is complete for finding-only input");
        String block = FindingBindings.formatFactsBlock(assembled,
                com.aq.jvmsentinel.provider.AiOutputLanguage.ZH_CN);
        check(block.contains("truncated=true"),
                "FINDING_BINDINGS_FACTS prompt marks truncated when > MAX_PROMPT_BINDINGS");
        check(block.contains("maxPromptBindings=") || block.contains("maxBindings="),
                "prompt truncation names prompt budget");
        check(block.contains("facts_search kind=FINDING"), "truncation hint names FINDING tool");
    }

    /** PathTrace facts 须内联 events，并在窗口外标记 eventsTruncated。 */
    private static void pathTraceEventsWindowMarkedWhenTruncated() {
        List<com.aq.jvmsentinel.domain.pathdebug.TraceEvent> events = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            events.add(new com.aq.jvmsentinel.domain.pathdebug.TraceEvent(
                    i, com.aq.jvmsentinel.domain.pathdebug.TraceEventKind.METHOD_HOP,
                    "hop-" + i, "subj", "", false, Map.of(), ""));
        }
        var posture = new com.aq.jvmsentinel.domain.pathdebug.RuntimePosture(
                com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind.COVERAGE_POSTURE,
                "TEST", List.of(), false, "COVERAGE");
        var trace = new com.aq.jvmsentinel.domain.pathdebug.PathTrace(
                com.aq.jvmsentinel.domain.pathdebug.PathTrace.SCHEMA_VERSION,
                "pt-1", "pr-1", "attempt-1", "", "", "entry:e1", "COVERAGE",
                posture, "", "corr-1", 0, events, List.of(),
                com.aq.jvmsentinel.domain.pathdebug.TraceExitReason.COMPLETED,
                "last", List.of(), false);
        var node = com.aq.jvmsentinel.ai.tool.datasource.PathRunFactSupport.pathTraceFact(trace);
        check(node.path("eventCount").asInt() == 40, "eventCount=40");
        check(node.path("events").size() == 32, "default events window 32");
        check(node.path("eventsTruncated").asBoolean(false), "eventsTruncated=true");
        check(node.path("eventsHasMore").asBoolean(false), "eventsHasMore=true");
        var continued = com.aq.jvmsentinel.ai.tool.datasource.PathRunFactSupport
                .pathTraceFact(trace, 32, 32);
        check(continued.path("events").size() == 8, "eventsOffset continuation returns remainder");
        check(!continued.path("eventsHasMore").asBoolean(true), "no more after offset 32");
    }

    /** 无 SQLite AI job 表时，scan_memory_get 应降级为空 priors，不得整工具 FAILED。 */
    private static void scanMemorySurvivesMissingAiJobStore() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-mem-degrade", "mem-degrade", now, "test");
        String digest = "b".repeat(64);
        String scanId = "scan-mem-degrade";
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");
        AiToolRegistry registry = new AiToolRegistry(new ControlPlaneToolDataSource(store, scanId));
        ObjectNode args = JSON.createObjectNode();
        args.put("section", "FACTS");
        ToolResult result = registry.execute(
                new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, "mem-degrade", "scan_memory_get", args),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", project.projectId()),
                        "principal", "job-degrade", AgentRole.PRE_ANALYSIS,
                        new ToolExecutionContext.Budget(4, 4096, 8, 64_000, Instant.now().plusSeconds(60))));
        check(result.status() == ToolStatus.SUCCESS,
                "scan_memory_get degrades without aiJobs store (was "
                        + result.status() + "/" + result.errorCode() + ")");
    }

    private static void scanMemoryInvalidRoleRejected() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-mem-role", "mem-role", now, "test");
        String digest = "e".repeat(64);
        String scanId = "scan-mem-role";
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");

        AiToolRegistry registry = new AiToolRegistry(new ControlPlaneToolDataSource(store, scanId));
        ObjectNode args = JSON.createObjectNode();
        args.put("section", "ROLE_SLICE");
        args.put("role", "NOT_A_REAL_ROLE");
        ToolResult result = registry.execute(
                new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, "mem-bad-role", "scan_memory_get", args),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", project.projectId()),
                        "principal", "job-1", AgentRole.PATH_EXPLORATION,
                        new ToolExecutionContext.Budget(4, 4096, 8, 64_000, Instant.now().plusSeconds(60))));
        check(result.status() == ToolStatus.INVALID_ARGUMENTS,
                "invalid ROLE_SLICE role is INVALID_ARGUMENTS (was "
                        + result.status() + "/" + result.errorCode() + ")");
        check("SCAN_MEMORY_ROLE_INVALID".equals(result.errorCode()),
                "errorCode=SCAN_MEMORY_ROLE_INVALID not silent INDEX");
    }

    private static void sinkIndexPrefersHighImpactBeforeTruncate() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-sink-rank", "Sink rank", now, "local-admin");
        String digest = "f".repeat(64);
        String scanId = "scan-sink-rank";
        List<ApiDtos.SinkDto> sinks = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            sinks.add(new ApiDtos.SinkDto(
                    ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId, "sink-low-" + i,
                    "LOGGING", "Logger.info" + i, "BYTECODE", ApiDtos.STATIC_INFERRED, 0.2, List.of()));
        }
        sinks.add(new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId, "sink-shiro-cmd",
                "COMMAND", "Runtime.exec", "BYTECODE", ApiDtos.STATIC_INFERRED, 0.95, List.of()));
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), sinks, List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        Map<String, Object> full = ScanMemoryBuilder.build(store, scanId, List.of(), Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> facts = (Map<String, Object>) full.get("facts");
        check(Boolean.TRUE.equals(facts.get("sinkIndexTruncated")), "sinkIndexTruncated when >48");
        check(Integer.valueOf(51).equals(facts.get("sinkIndexTotal")), "sinkIndexTotal=51");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sinkIndex = (List<Map<String, Object>>) facts.get("sinkIndex");
        check(sinkIndex.size() == 48, "sinkIndex capped at 48");
        boolean hasCommand = sinkIndex.stream().anyMatch(row -> "sink-shiro-cmd".equals(row.get("sinkId")));
        check(hasCommand, "high-impact COMMAND sink retained after MAX_INDEX truncate");
    }

    private static void triageGuidanceMentionsH4Effect() {
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        var project = store.createProject("project-triage-hint", "Triage hint", now, "local-admin");
        String digest = "a".repeat(64);
        String scanId = "scan-triage-hint";
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");
        Map<String, Object> built = ScanMemoryBuilder.build(store, scanId, List.of(), Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> slices = (Map<String, Object>) built.get("roleSlices");
        String triage = String.valueOf(slices.get(AgentRole.VULNERABILITY_TRIAGE.name()));
        check(triage.contains("H4"), "TRIAGE roleSlice guidance mentions H4");
        check(triage.contains("EFFECT"), "TRIAGE roleSlice guidance mentions EFFECT path");
        check(!triage.contains("仅 SQL H3"), "TRIAGE guidance must not claim SQL-H3-only confirmation");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}
