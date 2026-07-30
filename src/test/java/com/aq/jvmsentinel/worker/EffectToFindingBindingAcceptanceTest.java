package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.datasource.PathRunFactSupport;
import com.aq.jvmsentinel.analysis.experiment.PathTraceProjectionBridge;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 验收：新 JDK effectKind（FILE_WRITE 等）经投影 → H4 → Enricher → AI PATH_TRACE
 * 可关联回 finding/静态 sink；旧 EFFECT:FILE 仍兼容。
 */
public final class EffectToFindingBindingAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        fileWriteTargetSurvivesProjectionAndBindsFinding();
        legacyFileKindStillConfirmsAndBinds();
        fileReadDoesNotBindWriteFinding();
        pathTraceFactExposesTargetForAiTools();

        System.out.println("EffectToFindingBindingAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void fileWriteTargetSurvivesProjectionAndBindsFinding() {
        AgentJsonlTraceConverter.AgentEvent effect = agentEffect(
                "FILE",
                "com.example.UploadService",
                "save",
                "FILE_WRITE",
                "org.springframework.web.multipart.MultipartFile",
                "transferTo",
                "write",
                "/tmp/upload.bin");
        ApiDtos.PathRunDto run = pathRun("pr-fw", "entry:POST:/common/fileUpload",
                "POST", "/common/fileUpload");
        PathTrace trace = PathTraceProjectionBridge.projectFromPathRun(run, null, List.of(effect));

        check(trace.effectRefs().stream().anyMatch(r -> r.contains("EFFECT:FILE_WRITE")),
                "effectRefs must include EFFECT:FILE_WRITE");
        check(trace.effectRefs().stream().anyMatch(r ->
                        r.contains("MultipartFile") && r.contains("transferTo")),
                "effectRefs must include sink symbol MultipartFile#transferTo for reverse bind");
        TraceEvent effectEvent = trace.events().stream()
                .filter(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED)
                .findFirst()
                .orElseThrow();
        check("org.springframework.web.multipart.MultipartFile"
                        .equals(effectEvent.attributes().get("targetClass")),
                "TraceEvent.attributes.targetClass preserved");
        check("transferTo".equals(effectEvent.attributes().get("targetMethod")),
                "TraceEvent.attributes.targetMethod preserved");
        check("write".equals(effectEvent.attributes().get("effectOp")),
                "TraceEvent.attributes.effectOp preserved");

        PathRun model = TraceProjectionService.toPathRunModel(run);
        check(DynamicConfirmedGate.evaluateEffect(model, trace, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "H4 confirms FILE_WRITE finding property against FILE_WRITE effect");

        ApiDtos.FindingDto finding = finding(
                "finding-upload", "entry-upload", "/common/fileUpload",
                "org.springframework.web.multipart.MultipartFile#transferTo",
                "FILE_WRITE");
        ApiDtos.EntryDto entry = entry("entry-upload", "POST", "/common/fileUpload");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                finding, List.of(entry), List.of(run), Map.of(run.pathRunId(), trace),
                p -> "文件写入");
        check(ApiDtos.DYNAMIC_CONFIRMED.equals(enrichment.verificationStatus()),
                "Enricher binds FILE_WRITE effect → finding on same entry");
        check(enrichment.pathRunRefs().contains(run.pathRunId()),
                "Enricher pathRunRefs includes effect PathRun");
        check(FindingRuntimeEnricher.sinkSymbolOverlaps(
                        finding.sink().toLowerCase(),
                        "org.springframework.web.multipart.MultipartFile#transferTo".toLowerCase()),
                "sink reverse: finding.sink overlaps runtime MultipartFile#transferTo");
    }

    private static void legacyFileKindStillConfirmsAndBinds() {
        AgentJsonlTraceConverter.AgentEvent effect = agentEffect(
                "FILE",
                "com.example.OldUpload",
                "store",
                "FILE",
                "org.springframework.web.multipart.MultipartFile",
                "transferTo",
                "write",
                "");
        ApiDtos.PathRunDto run = pathRun("pr-legacy", "entry:POST:/ueditor/upload",
                "POST", "/ueditor/upload");
        PathTrace trace = PathTraceProjectionBridge.projectFromPathRun(run, null, List.of(effect));
        check(trace.effectRefs().stream().anyMatch(r -> r.equals("EFFECT:FILE") || r.contains("EFFECT:FILE")),
                "legacy EFFECT:FILE still projected");
        check(DynamicConfirmedGate.evaluateEffect(
                        TraceProjectionService.toPathRunModel(run), trace, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "legacy FILE kind still confirms FILE_WRITE property");

        ApiDtos.FindingDto finding = finding(
                "finding-legacy", "entry-ueditor", "/ueditor/upload",
                "MultipartFile#transferTo", "FILE_WRITE");
        ApiDtos.EntryDto entry = entry("entry-ueditor", "POST", "/ueditor/upload");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                finding, List.of(entry), List.of(run), Map.of(run.pathRunId(), trace),
                p -> "文件写入");
        check(ApiDtos.DYNAMIC_CONFIRMED.equals(enrichment.verificationStatus()),
                "legacy FILE effect still binds FILE_WRITE finding");
    }

    private static void fileReadDoesNotBindWriteFinding() {
        AgentJsonlTraceConverter.AgentEvent effect = agentEffect(
                "FILE",
                "com.example.Download",
                "read",
                "FILE_READ",
                "java.io.FileInputStream",
                "<init>",
                "read",
                "/etc/passwd");
        ApiDtos.PathRunDto run = pathRun("pr-read", "entry:GET:/common/download",
                "GET", "/common/download");
        PathTrace trace = PathTraceProjectionBridge.projectFromPathRun(run, null, List.of(effect));
        check(trace.effectRefs().stream().anyMatch(r -> r.contains("EFFECT:FILE_READ")),
                "FILE_READ projected");
        check(DynamicConfirmedGate.evaluateEffect(
                        TraceProjectionService.toPathRunModel(run), trace, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "FILE_READ must not confirm FILE_WRITE");

        ApiDtos.FindingDto writeFinding = finding(
                "finding-write-on-download", "entry-dl", "/common/download",
                "java.io.FileOutputStream#<init>", "FILE_WRITE");
        ApiDtos.EntryDto entry = entry("entry-dl", "GET", "/common/download");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                writeFinding, List.of(entry), List.of(run), Map.of(run.pathRunId(), trace),
                p -> "文件写入");
        check(ApiDtos.STATIC_INFERRED.equals(enrichment.verificationStatus())
                        || ApiDtos.DYNAMIC_SUSPECTED.equals(enrichment.verificationStatus()),
                "FILE_READ must not elevate FILE_WRITE finding");
        check(!ApiDtos.DYNAMIC_CONFIRMED.equals(enrichment.verificationStatus()),
                "FILE_WRITE finding stays unconfirmed under FILE_READ only");
    }

    private static void pathTraceFactExposesTargetForAiTools() {
        AgentJsonlTraceConverter.AgentEvent effect = agentEffect(
                "HTTP_CLIENT",
                "com.example.Client",
                "fetch",
                "SSRF",
                "java.net.http.HttpClient",
                "send",
                "connect",
                "http://169.254.169.254/");
        ApiDtos.PathRunDto run = pathRun("pr-ssrf", "entry:GET:/proxy", "GET", "/proxy");
        PathTrace trace = PathTraceProjectionBridge.projectFromPathRun(run, null, List.of(effect));
        JsonNode fact = PathRunFactSupport.pathTraceFact(trace);
        check("PATH_TRACE".equals(fact.path("kind").asText()), "facts_search PATH_TRACE kind");
        boolean sawTarget = false;
        for (JsonNode event : fact.path("events")) {
            if (!"EFFECT_TRIGGERED".equals(event.path("kind").asText())) continue;
            JsonNode attrs = event.path("attributes");
            if ("java.net.http.HttpClient".equals(attrs.path("targetClass").asText())
                    && "send".equals(attrs.path("targetMethod").asText())
                    && "SSRF".equals(attrs.path("effectKind").asText())) {
                sawTarget = true;
            }
        }
        check(sawTarget, "AI PATH_TRACE fact exposes targetClass/targetMethod/effectKind");
        check(fact.path("effectRefs").toString().contains("EFFECT:SSRF"),
                "AI PATH_TRACE fact.effectRefs includes EFFECT:SSRF");
        check(fact.path("effectRefs").toString().contains("HttpClient"),
                "AI PATH_TRACE fact.effectRefs includes HttpClient sink symbol");
    }

    private static AgentJsonlTraceConverter.AgentEvent agentEffect(
            String eventType,
            String callerClass,
            String callerMethod,
            String effectKind,
            String targetClass,
            String targetMethod,
            String effectOp,
            String pathOrUrl) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("pathDebugKind", "EFFECT_TRIGGERED");
        detail.put("effectKind", effectKind);
        detail.put("captureMode", "APPLICATION_CALL_SITE");
        detail.put("targetClass", targetClass);
        detail.put("targetMethod", targetMethod);
        detail.put("effectOp", effectOp);
        detail.put("correlationId", "corr-bind-1");
        detail.put("requestBound", "true");
        if (pathOrUrl != null && !pathOrUrl.isBlank()) {
            detail.put("pathOrUrl", pathOrUrl);
        }
        return new AgentJsonlTraceConverter.AgentEvent(
                1, eventType, "AGENT_INSTRUMENTED", "DYNAMIC_SUSPECTED",
                callerClass, callerMethod, "2026-07-30T00:00:00Z", "http-1", detail);
    }

    private static ApiDtos.PathRunDto pathRun(
            String pathRunId, String entryRef, String method, String route) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, pathRunId, "scan-1", entryRef,
                "ADMIN", "corr-bind-1", "plan:posture:x:forced_reachability", method,
                "application/json", method + " " + route, "HTTP_OBSERVED", 200,
                true, true, List.of(), "COMPLETED", "DYNAMIC_SUSPECTED",
                List.of("ev-" + pathRunId), "MOCK", "synthetic");
    }

    private static ApiDtos.FindingDto finding(
            String id, String entryId, String route, String sink, String property) {
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1", id,
                "静态推断信号", "high", ApiDtos.STATIC_INFERRED,
                entryId, route, "sink-" + id, sink,
                "none", List.of("none"), List.of("ev-static"), 1, 0.8, ApiDtos.MOCK, null,
                "hyp-" + id, property);
    }

    private static ApiDtos.EntryDto entry(String entryId, String method, String route) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1",
                entryId, "HTTP", method, route, "demo.C", "C",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
