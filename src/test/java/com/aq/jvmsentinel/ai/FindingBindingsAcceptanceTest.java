package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.provider.AiOutputLanguage;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * PATH findingBindings + REPORT locale-pure Vulnerabilities section from FORCED/STATIC materials.
 */
public final class FindingBindingsAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        forcedBindingEmitsInstrumentationPoc();
        staticBindingSaysNoPoc();
        reportSectionLocalePureZh();
        authGapWithoutCooperationIsRiskPointAtBottom();
        languageInstructionLocalePure();
        System.out.println("FindingBindingsAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void forcedBindingEmitsInstrumentationPoc() {
        ApiDtos.EntryDto entry = entry("entry-ann-42", "POST", "/ueditor/upload");
        ApiDtos.FindingDto finding = finding(
                "finding-1", "静态推断的文件写入信号", "entry-ann-42", "/ueditor/upload");
        ApiDtos.PathRunDto run = pathRun(
                "pr-forced", "entry:POST:/ueditor/upload", 200, true,
                "plan:posture:entry-ann-42:forced_reachability");
        PathTrace trace = forcedTraceWithHops("pr-forced", "entry:entry-ann-42");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(run),
                Map.of("pr-forced", trace), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "one binding assembled");
        FindingBindings.Binding binding = bindings.get(0);
        check("POST".equals(binding.api().method()) && "/ueditor/upload".equals(binding.api().route()),
                "api method+route bound");
        check(binding.api().entryRef().contains("entry-ann-42"), "entryRef bound");
        check(RuntimePosture.PROVENANCE_INSTRUMENTATION.equals(binding.poc().provenance()),
                "FORCED poc provenance=INSTRUMENTATION_REACHABILITY");
        check("EXPERIMENT_HINT".equals(binding.poc().kind()), "FORCED poc kind=EXPERIMENT_HINT");
        check(binding.poc().steps().stream().anyMatch(s -> s.contains("FORCED_REACHABILITY")),
                "PoC mentions FORCED_REACHABILITY");
        check(binding.poc().steps().stream().anyMatch(s -> s.contains("CommonController")
                        || s.contains("FileService")),
                "PoC includes business METHOD_HOP subjects");
        check(binding.pathRunRefs().contains("pr-forced"), "pathRunRefs include forced run");
        check(ApiDtos.STATIC_INFERRED.equals(binding.status()),
                "status remains STATIC_INFERRED (no VERIFIED elevation)");
        check(!binding.description().isBlank(), "description non-empty");
    }

    private static void staticBindingSaysNoPoc() {
        ApiDtos.EntryDto entry = entry("entry-ann-9", "GET", "/admin");
        ApiDtos.FindingDto finding = finding(
                "finding-2", "静态推断的鉴权缺口信号", "entry-ann-9", "/admin");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "static binding present");
        check(bindings.get(0).poc().steps().stream().anyMatch(s -> s.contains(FindingBindings.NO_POC_ZH)),
                "STATIC without PathRun writes 暂无 PoC");
        check("STATIC_HINT".equals(bindings.get(0).poc().kind()), "STATIC_HINT kind");
    }

    private static void reportSectionLocalePureZh() {
        ApiDtos.EntryDto entry = entry("entry-ann-1", "GET", "/home");
        ApiDtos.FindingDto finding = finding(
                "finding-3", "强达路径风险材料", "entry-ann-1", "/home");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        String thinMixed = "# Audit Report\n\n## Vulnerabilities\n\nthin\n";
        FindingBindings.EnforceResult enforced = FindingBindings.enforceReportSection(
                thinMixed, bindings, AiOutputLanguage.ZH_CN);
        check(enforced.appendedByServer() || enforced.localeRepaired(),
                "server repairs thin/mixed report");
        check(enforced.summary().contains(FindingBindings.SECTION_ZH),
                "ZH report contains ## 漏洞相关");
        check(enforced.summary().contains("/home"), "section includes API route");
        check(enforced.summary().contains("PoC") || enforced.summary().contains("复现")
                        || enforced.summary().contains(FindingBindings.NO_POC_ZH),
                "section includes PoC marker");
        check(!enforced.summary().contains("## Vulnerabilities"),
                "locale-pure ZH must not retain ## Vulnerabilities header");
    }

    private static void authGapWithoutCooperationIsRiskPointAtBottom() {
        ApiDtos.EntryDto leave = entry("entry-ann-1", "GET", "/blade-desk/process/leave/detail");
        ApiDtos.EntryDto jwtEntry = entry("entry-ann-159", "GET", "/blade-auth/oauth/logout");
        ApiDtos.FindingDto authGap = findingWithProperty(
                "finding-auth-gap", "静态推断的鉴权缺口信号", "entry-ann-1",
                "/blade-desk/process/leave/detail", "AUTH_GAP");
        ApiDtos.FindingDto jwt = findingWithProperty(
                "finding-jwt", "静态推断的硬编码/默认 JWT 签名密钥信号", "entry-ann-159",
                "/blade-auth/oauth/logout", "HARDCODED_JWT_SIGN_KEY");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(authGap, jwt), List.of(leave, jwtEntry), List.of(), Map.of(),
                AiOutputLanguage.ZH_CN);
        check(bindings.size() == 2, "two bindings assembled");
        check(FindingBindings.REPORT_ROLE_PRIMARY.equals(bindings.get(0).reportRole()),
                "JWT/high-impact binding is PRIMARY and sorted first");
        check(bindings.get(0).findingId().equals("finding-jwt"),
                "PRIMARY JWT finding precedes AUTH_GAP risk point");
        check(FindingBindings.REPORT_ROLE_RISK_POINT.equals(bindings.get(1).reportRole()),
                "AUTH_GAP without cooperation is RISK_POINT");
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        int vulnIdx = md.indexOf(FindingBindings.SECTION_ZH);
        int riskIdx = md.indexOf(FindingBindings.RISK_SECTION_ZH);
        check(vulnIdx >= 0 && riskIdx > vulnIdx, "风险点 section follows 漏洞相关");
        check(md.contains("JWT") && md.indexOf("JWT") < riskIdx,
                "primary section mentions JWT material before 风险点");
        check(md.contains("风险点（非主漏洞）") || md.contains("仅作风险标注"),
                "risk section labels non-primary risk points");
        FindingBindings.EnforceResult enforced = FindingBindings.enforceReportSection(
                "# 审计报告\n\n## 漏洞相关\n\nthin\n", bindings, AiOutputLanguage.ZH_CN);
        check(enforced.summary().contains(FindingBindings.RISK_SECTION_ZH),
                "server enforce appends ## 风险点 when RISK_POINT bindings exist");
    }

    private static void languageInstructionLocalePure() throws Exception {
        Method languageInstruction = AiJobOrchestrator.class.getDeclaredMethod(
                "languageInstruction", AiOutputLanguage.class);
        languageInstruction.setAccessible(true);
        String zh = (String) languageInstruction.invoke(null, AiOutputLanguage.ZH_CN);
        String en = (String) languageInstruction.invoke(null, AiOutputLanguage.EN);
        check(zh.contains("locale-pure") || zh.contains("不得夹杂"),
                "ZH languageInstruction requires locale purity");
        check(zh.contains("## Vulnerabilities"), "ZH forbids English ## Vulnerabilities");
        check(en.contains("locale-pure") || en.contains("must not mix"),
                "EN languageInstruction requires locale purity");
        check(en.contains("## 漏洞相关"), "EN forbids Chinese ## 漏洞相关");

        Method roleInstruction = AiJobOrchestrator.class.getDeclaredMethod(
                "roleInstruction",
                com.aq.jvmsentinel.provider.AgentRole.class,
                AiOutputLanguage.class);
        roleInstruction.setAccessible(true);
        String reportZh = (String) roleInstruction.invoke(
                null, com.aq.jvmsentinel.provider.AgentRole.REPORT_GENERATION, AiOutputLanguage.ZH_CN);
        check(reportZh.contains("FINDING_BINDINGS_FACTS") || reportZh.contains("findingBindings"),
                "ZH REPORT consumes FINDING_BINDINGS_FACTS / findingBindings");
        check(reportZh.contains("locale-pure") || reportZh.contains("禁止英文专章"),
                "ZH REPORT requires locale-pure Chinese");
        check(reportZh.contains("【必填章节】") && reportZh.contains("【Markdown 骨架"),
                "ZH REPORT prompt includes required-section outline and Markdown skeleton");
        check(reportZh.contains("暂无 PoC") && reportZh.contains("INSTRUMENTATION_REACHABILITY"),
                "ZH REPORT template requires honest PoC / FORCED provenance");
        check(reportZh.contains("## 风险点") && reportZh.contains("reportRole=RISK_POINT"),
                "ZH REPORT template requires trailing 风险点 / RISK_POINT ordering gate");
        check(reportZh.contains("ADR-0004"), "ZH REPORT keeps ADR-0004 posture honesty");
    }

    private static ApiDtos.EntryDto entry(String id, String method, String route) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a",
                id, "HTTP", method, route, "com.kalvin.kvf.common.controller.C", "C",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static ApiDtos.FindingDto finding(
            String id, String title, String entryId, String route) {
        return findingWithProperty(id, title, entryId, route, "FILE_WRITE");
    }

    private static ApiDtos.FindingDto findingWithProperty(
            String id, String title, String entryId, String route, String securityProperty) {
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a", id, title, "high",
                ApiDtos.STATIC_INFERRED, entryId, route, "sink-1", "sink", "none",
                List.of("none"), List.of("ev-1"), 1, 0.7, ApiDtos.MOCK, null,
                "hyp-1", securityProperty);
    }

    private static ApiDtos.PathRunDto pathRun(
            String id, String entryRef, int http, boolean entryHit, String planId) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, "scan-a", entryRef, "ADMIN", "attempt-1",
                planId, "POST", "application/json",
                "POST /ueditor/upload track=ADMIN correlationId=req-1 experimentPlanId=" + planId,
                "HTTP_OBSERVED", http, entryHit, true, List.of(), "HTTP_OBSERVED",
                ApiDtos.DYNAMIC_SUSPECTED, List.of("ev-" + id), "MOCK", "");
    }

    private static PathTrace forcedTraceWithHops(String pathRunId, String entryRef) {
        List<TraceEvent> events = List.of(
                new TraceEvent(1, TraceEventKind.ENTRY_HIT, "POST /ueditor/upload", entryRef,
                        "", false, Map.of(), ""),
                new TraceEvent(2, TraceEventKind.GUARD_DECISION, "FORCED_ALLOW at LoginFilter",
                        "com.kalvin.kvf.common.shiro.LoginFilter", "FORCED_ALLOW", true, Map.of(), ""),
                new TraceEvent(3, TraceEventKind.METHOD_HOP,
                        "APPLICATION_METHOD at CommonController#upload",
                        "com.kalvin.kvf.common.controller.CommonController#upload",
                        "", false, Map.of(), ""),
                new TraceEvent(4, TraceEventKind.METHOD_HOP,
                        "APPLICATION_METHOD at FileService#store",
                        "com.kalvin.kvf.common.service.FileService#store",
                        "", false, Map.of(), ""));
        return new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace:" + pathRunId,
                pathRunId,
                "probe-1",
                "plan:posture:forced_reachability:entry",
                "traceplan-1",
                entryRef,
                "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "world-1",
                "corr-1",
                1,
                events,
                List.of(),
                TraceExitReason.COMPLETED,
                "com.kalvin.kvf.common.service.FileService#store",
                List.of(),
                false);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
