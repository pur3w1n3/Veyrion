package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.analysis.experiment.PathTraceProjector;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * H4 sink-effect confirmation + requiredPrivilege；FORCED-only 不得误升。
 */
public final class EffectConfirmationGateAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        forcedOnlyMustNotConfirm();
        expressionEffectConfirmsWithPrivilege();
        jdbcEffectConfirms();
        fileWriteEffectConfirms();
        fileReadObservedButDoesNotConfirmTraversal();
        dnsLookupDoesNotConfirmSsrf();
        observeDoesNotAutoConfirmWithoutEntryOrEvidence();
        enricherElevatesOnlyWithEffect();
        pathRunConfirmedWithoutPropertyMatchDoesNotElevateFinding();

        System.out.println("EffectConfirmationGateAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void forcedOnlyMustNotConfirm() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:x:forced_reachability");
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:forced-only", run.pathRunId(), run.attemptId(), run.experimentPlanId(),
                "", run.entrypointRef(), run.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-1", 1,
                List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.ENTRY_HIT, "POST entry", run.entrypointRef(),
                        "", false, List.of())),
                List.of(), 64, "INSTRUMENTATION_REACHABILITY"));
        check(DynamicConfirmedGate.evaluateEffect(run, trace, "EXPRESSION")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "FORCED ENTRY_HIT without EFFECT must not confirm");
        check(RequiredPrivilege.codeFor(run, trace, false)
                        .equals(RequiredPrivilege.INSTRUMENTED_ADMIN),
                "forced track projects INSTRUMENTED_ADMIN privilege code");
    }

    private static void expressionEffectConfirmsWithPrivilege() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:x:forced_reachability");
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:expr", run.pathRunId(), run.attemptId(), run.experimentPlanId(),
                "", run.entrypointRef(), run.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-expr", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST entry", run.entrypointRef(),
                                "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED,
                                "EXPRESSION at GenServiceImpl#CheckCode",
                                "com.ql.util.express.ExpressRunner#execute",
                                "EFFECT:EXPRESSION", false, List.of("EFFECT:EXPRESSION"))),
                List.of(), 64, "INSTRUMENTATION_REACHABILITY"));
        check(DynamicConfirmedGate.evaluateEffect(run, trace, "EXPRESSION")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "EXPRESSION EFFECT_TRIGGERED → DYNAMIC_CONFIRMED");
        PathRun applied = DynamicConfirmedGate.applyEffect(run, trace, "EXPRESSION");
        check(VerificationStatus.DYNAMIC_CONFIRMED.name().equals(applied.verificationStatus()),
                "applyEffect upgrades PathRun");
        String label = RequiredPrivilege.humanLabel(
                RequiredPrivilege.codeFor(applied, trace, false), true);
        check(label.contains("管理员") || label.contains("强达"),
                "confirmed forced path labels admin-equivalent privilege: " + label);
    }

    private static void jdbcEffectConfirms() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:x:forced_reachability");
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:jdbc", run.pathRunId(), run.attemptId(), run.experimentPlanId(),
                "", "entry:POST:/common/test-connection", run.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-jdbc", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST entry",
                                "entry:POST:/common/test-connection", "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "SSRF at DriverManager",
                                "java.sql.DriverManager#getConnection",
                                "EFFECT:SSRF", false, List.of("EFFECT:SSRF", "EFFECT:JDBC"))),
                List.of(), 64, ""));
        check(DynamicConfirmedGate.evaluateEffect(run, trace, "SSRF")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "JDBC/SSRF effect confirms SSRF finding");
    }

    private static void fileWriteEffectConfirms() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:entry-ann-88:forced_reachability");
        PathRun uploadRun = new PathRun(
                run.pathRunId(), run.scanId(), "entry:POST:/common/fileUpload", run.track(),
                run.attemptId(), run.experimentPlanId(), run.method(), "multipart/form-data",
                "POST /common/fileUpload", run.outcomeClass(), run.httpStatus(), run.entryHit(),
                run.parameterBound(), run.sqlEvents(), run.stopReason(), run.verificationStatus(),
                run.evidenceRefs(), run.identityProvenance(), run.identityPrecondition(),
                run.branchHitMap());
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:file", uploadRun.pathRunId(), uploadRun.attemptId(),
                uploadRun.experimentPlanId(), "", uploadRun.entrypointRef(), uploadRun.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-file", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST entry",
                                uploadRun.entrypointRef(), "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "FILE at MultipartFile#transferTo",
                                "org.springframework.web.multipart.MultipartFile#transferTo",
                                "EFFECT:FILE", false, List.of("EFFECT:FILE"))),
                List.of(), 64, "INSTRUMENTATION_REACHABILITY"));
        check(DynamicConfirmedGate.evaluateEffect(uploadRun, trace, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "legacy FILE / FILE_WRITE effect confirms FILE_WRITE finding");
        check(DynamicConfirmedGate.evaluateEffect(uploadRun, trace, "PATH_TRAVERSAL")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "FILE_WRITE-shaped effect confirms PATH_TRAVERSAL");
        check(DynamicConfirmedGate.evaluateEffect(uploadRun, trace, "EXPRESSION")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "FILE effect must not confirm unrelated EXPRESSION finding");

        PathTrace writeKind = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:file-write", uploadRun.pathRunId(), uploadRun.attemptId(),
                uploadRun.experimentPlanId(), "", uploadRun.entrypointRef(), uploadRun.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-fw", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST entry",
                                uploadRun.entrypointRef(), "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "FILE_WRITE at Files.write",
                                "java.nio.file.Files#write",
                                "EFFECT:FILE_WRITE", false, List.of("EFFECT:FILE_WRITE"))),
                List.of(), 64, "INSTRUMENTATION_REACHABILITY"));
        check(DynamicConfirmedGate.evaluateEffect(uploadRun, writeKind, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "FILE_WRITE kind confirms FILE_WRITE");
    }

    private static void fileReadObservedButDoesNotConfirmTraversal() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:entry-ann-88:forced_reachability");
        PathRun readRun = new PathRun(
                run.pathRunId(), run.scanId(), "entry:GET:/common/download", run.track(),
                run.attemptId(), run.experimentPlanId(), "GET", "application/json",
                "GET /common/download", run.outcomeClass(), run.httpStatus(), run.entryHit(),
                run.parameterBound(), run.sqlEvents(), run.stopReason(), run.verificationStatus(),
                run.evidenceRefs(), run.identityProvenance(), run.identityPrecondition(),
                run.branchHitMap());
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:file-read", readRun.pathRunId(), readRun.attemptId(),
                readRun.experimentPlanId(), "", readRun.entrypointRef(), readRun.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-fr", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "GET entry",
                                readRun.entrypointRef(), "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "FILE_READ at FileInputStream",
                                "java.io.FileInputStream#<init>",
                                "EFFECT:FILE_READ", false, List.of("EFFECT:FILE_READ"))),
                List.of(), 64, "INSTRUMENTATION_REACHABILITY"));
        check(DynamicConfirmedGate.evaluateEffect(readRun, trace, "FILE_READ")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "FILE_READ may confirm explicit FILE_READ property");
        check(DynamicConfirmedGate.evaluateEffect(readRun, trace, "PATH_TRAVERSAL")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "FILE_READ alone must not confirm PATH_TRAVERSAL");
        check(DynamicConfirmedGate.evaluateEffect(readRun, trace, "FILE_WRITE")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "FILE_READ must not confirm FILE_WRITE");
        check(DynamicConfirmedGate.evaluateEffect(readRun, trace, "")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "blank property: FILE_READ is not a strong confirmable kind");
    }

    private static void dnsLookupDoesNotConfirmSsrf() {
        PathRun run = baseRun(IdentityTrack.ADMIN, "plan:posture:x:forced_reachability");
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:dns", run.pathRunId(), run.attemptId(), run.experimentPlanId(),
                "", run.entrypointRef(), run.track().name(),
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "worldpack:mock", "corr-dns", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST entry", run.entrypointRef(),
                                "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "DNS_LOOKUP",
                                "java.net.InetAddress#getByName",
                                "EFFECT:DNS_LOOKUP", false, List.of("EFFECT:DNS_LOOKUP"))),
                List.of(), 64, ""));
        check(DynamicConfirmedGate.evaluateEffect(run, trace, "SSRF")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "DNS_LOOKUP must not confirm SSRF");
        check(DynamicConfirmedGate.evaluateEffect(run, trace, "")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "DNS_LOOKUP must not strong-confirm blank property");
    }

    private static void observeDoesNotAutoConfirmWithoutEntryOrEvidence() {
        PathRun noEvidence = new PathRun(
                "pr-ne", "scan-1", "entry:POST:/x", IdentityTrack.ADMIN, "a1",
                "plan:posture:x:forced_reachability", "POST", "application/json", "POST /x",
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true, List.of(),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of(), "MOCK", "synthetic");
        PathTrace withEffect = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:ne", noEvidence.pathRunId(), noEvidence.attemptId(),
                noEvidence.experimentPlanId(), "", noEvidence.entrypointRef(), "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "", "corr-ne", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST", noEvidence.entrypointRef(),
                                "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "SSRF",
                                "java.net.URL#openConnection", "EFFECT:SSRF", false,
                                List.of("EFFECT:SSRF"))),
                List.of(), 32, ""));
        check(DynamicConfirmedGate.evaluateEffect(noEvidence, withEffect, "SSRF")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "EFFECT without evidenceRefs must not confirm");
    }

    private static void enricherElevatesOnlyWithEffect() {
        ApiDtos.FindingDto finding = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1", "finding-expr",
                "静态推断的表达式/模板注入信号", "high", ApiDtos.STATIC_INFERRED,
                "entry-1", "/generator/check/code", "sink-1", "ExpressRunner#execute",
                "none", List.of("none"), List.of("ev-static"), 1, 0.8, ApiDtos.MOCK, null,
                "hyp-1", "EXPRESSION");
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1",
                "entry-1", "HTTP", "POST", "/generator/check/code", "demo.C", "C",
                List.of("code"), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
        ApiDtos.PathRunDto forcedOnly = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-forced", "scan-1", "entry:POST:/generator/check/code",
                "ADMIN", "corr-f", "plan:posture:entry-1:forced_reachability", "POST",
                "application/json", "POST /generator/check/code", "HTTP_OBSERVED", 200,
                true, null, List.of(), "COMPLETED", "DYNAMIC_SUSPECTED",
                List.of("ev-1"), "MOCK", "synthetic");
        PathTrace forcedTrace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:pr-forced", forcedOnly.pathRunId(), forcedOnly.attemptId(),
                forcedOnly.experimentPlanId(), "", forcedOnly.entrypointRef(), "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "", "corr-f", 1,
                List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.ENTRY_HIT, "POST", forcedOnly.entrypointRef(),
                        "", false, List.of())),
                List.of(), 32, ""));
        FindingRuntimeEnricher.Enrichment noEffect = FindingRuntimeEnricher.enrich(
                finding, List.of(entry), List.of(forcedOnly),
                Map.of(forcedOnly.pathRunId(), forcedTrace), p -> "表达式/模板注入");
        check(ApiDtos.STATIC_INFERRED.equals(noEffect.verificationStatus()),
                "enricher keeps STATIC_INFERRED for FORCED without effect");
        check(noEffect.requiredPrivilege().isBlank(),
                "no privilege label without confirmation");

        ApiDtos.PathRunDto withEffect = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-effect", "scan-1", "entry:POST:/generator/check/code",
                "ADMIN", "corr-e", "plan:posture:entry-1:forced_reachability", "POST",
                "application/json", "POST /generator/check/code", "HTTP_OBSERVED", 200,
                true, true, List.of(), "COMPLETED", "DYNAMIC_SUSPECTED",
                List.of("ev-2"), "MOCK", "synthetic");
        PathTrace effectTrace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:pr-effect", withEffect.pathRunId(), withEffect.attemptId(),
                withEffect.experimentPlanId(), "", withEffect.entrypointRef(), "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "", "corr-e", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "POST", withEffect.entrypointRef(),
                                "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "EXPRESSION",
                                "ExpressRunner#execute", "EFFECT:EXPRESSION", false,
                                List.of("EFFECT:EXPRESSION"))),
                List.of(), 32, ""));
        FindingRuntimeEnricher.Enrichment confirmed = FindingRuntimeEnricher.enrich(
                finding, List.of(entry), List.of(withEffect),
                Map.of(withEffect.pathRunId(), effectTrace), p -> "表达式/模板注入");
        check(ApiDtos.DYNAMIC_CONFIRMED.equals(confirmed.verificationStatus()),
                "enricher elevates to DYNAMIC_CONFIRMED with EXPRESSION effect");
        check(!confirmed.requiredPrivilege().isBlank(),
                "confirmed enrichment carries requiredPrivilege");
        Map<String, Object> wire = FindingRuntimeEnricher.applyToWire(Map.of(), confirmed);
        check("DYNAMIC_CONFIRMED".equals(wire.get("verificationStatus")),
                "wire verificationStatus confirmed");
        check(wire.get("requiredPrivilege") != null
                        && !wire.get("requiredPrivilege").toString().isBlank(),
                "wire exposes requiredPrivilege");
    }

    private static void pathRunConfirmedWithoutPropertyMatchDoesNotElevateFinding() {
        ApiDtos.FindingDto authGap = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1", "finding-auth",
                "静态推断的鉴权缺口信号", "low", ApiDtos.STATIC_INFERRED,
                "entry-1", "/ueditor/upload", "sink-auth", "guard-coverage",
                "none", List.of("none"), List.of("ev-static"), 1, 0.5, ApiDtos.MOCK, null,
                "hyp-auth", "AUTH_GAP");
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-1",
                "entry-1", "HTTP", "GET", "/ueditor/upload", "demo.C", "C",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
        ApiDtos.PathRunDto confirmedNoise = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-noise", "scan-1", "entry:GET:/ueditor/upload",
                "ADMIN", "corr-n", "plan:posture:entry-1:forced_reachability", "GET",
                "text/plain", "GET /ueditor/upload", "HTTP_OBSERVED", 200,
                true, true, List.of(), "COMPLETED", "DYNAMIC_CONFIRMED",
                List.of("ev-n"), "MOCK", "synthetic");
        PathTrace deserialTrace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:pr-noise", confirmedNoise.pathRunId(), confirmedNoise.attemptId(),
                confirmedNoise.experimentPlanId(), "", confirmedNoise.entrypointRef(), "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "", "corr-n", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "GET", confirmedNoise.entrypointRef(),
                                "", false, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.EFFECT_TRIGGERED, "DESERIALIZATION",
                                "org.apache.shiro.mgt.AbstractRememberMeManager#getRememberedPrincipals",
                                "EFFECT:DESERIALIZATION", false,
                                List.of("EFFECT:DESERIALIZATION"))),
                List.of(), 32, ""));
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                authGap, List.of(entry), List.of(confirmedNoise),
                Map.of(confirmedNoise.pathRunId(), deserialTrace), p -> "鉴权缺口");
        check(ApiDtos.STATIC_INFERRED.equals(enrichment.verificationStatus()),
                "PathRun DYNAMIC_CONFIRMED from unrelated DESERIAL must not elevate AUTH_GAP");
    }

    private static PathRun baseRun(IdentityTrack track, String planId) {
        return new PathRun(
                "pr-1", "scan-1", "entry:POST:/generator/check/code", track, "attempt-1",
                planId, "POST", "application/json", "POST /generator/check/code",
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true, List.of(),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("evidence-1"),
                "MOCK", "synthetic identity");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
