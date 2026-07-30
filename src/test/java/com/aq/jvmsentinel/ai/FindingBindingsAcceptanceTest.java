package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.prompt.AiPromptLanguage;
import com.aq.jvmsentinel.ai.prompt.AiRolePrompts;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.provider.AiOutputLanguage;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * PATH findingBindings + 可交付 REPORT Markdown（封面/摘要/关键发现/附录）。
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
        deliverableTemplateHasCoverSummaryAppendix();
        unboundApiUsesHumanLabel();
        keyFindingsGroupedBySeverityWithTechPath();
        exploitChainSectionFromAuthPlusDangerousSink();
        maxBindingsKeepsHighImpactAndConfirmed();
        languageInstructionLocalePure();
        effectConfirmedBindingSurfacesDynamicConfirmed();
        incidentalDeserialDoesNotConfirmUnrelatedFinding();
        maxBindingsPrefersForcedMaterialsOverStaticAuthGap();
        orphanSpelEffectBecomesConfirmedBinding();
        nullEntryHitForcedFillsMidLogicFromHops();
        orphanSpelNotBlockedByAuthGapOnSameEntry();
        orphanCapLeavesRoomForHighImpactFindings();
        executiveSummarySeparatesForcedFromPureStatic();
        rememberMeDeserialOrphansCollapse();
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
        check(binding.poc().steps().stream().anyMatch(s -> s.contains("授权沙箱") || s.contains("HTTP 200")),
                "PoC describes authorized-sandbox observation");
        check(binding.poc().steps().stream().anyMatch(s -> s.contains("CommonController")
                        || s.contains("FileService")),
                "PoC includes business METHOD_HOP subjects");
        check(binding.poc().steps().stream().anyMatch(s ->
                        s.contains("不能单独确认为漏洞") || s.contains("不得当作利用证明")
                                || s.contains("不能等同于匿名可利用") || s.contains("受控强达")),
                "PoC honesty note for forced reachability");
        check(binding.pathRunRefs().contains("pr-forced"), "pathRunRefs include forced run");
        check(ApiDtos.STATIC_INFERRED.equals(binding.status()),
                "status remains STATIC_INFERRED (no VERIFIED elevation)");
        check(!binding.description().isBlank(), "description non-empty");
        check(!binding.description().contains("kind="), "customer description omits poc.kind dump");
        check(binding.sink() != null && !binding.sink().isBlank(), "sink retained for appendix");
    }

    private static void staticBindingSaysNoPoc() {
        ApiDtos.EntryDto entry = entry("entry-ann-9", "GET", "/admin");
        ApiDtos.FindingDto finding = finding(
                "finding-2", "静态推断的鉴权缺口信号", "entry-ann-9", "/admin");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "static binding present");
        check(bindings.get(0).poc().steps().stream().anyMatch(s -> s.contains(FindingBindings.NO_POC_ZH)),
                "STATIC without PathRun writes 本轮未形成可复现 PoC");
        check("STATIC_HINT".equals(bindings.get(0).poc().kind()), "STATIC_HINT kind");
        check(bindings.get(0).poc().steps().stream().noneMatch(s ->
                        s.contains("UNAUTH") || s.contains("COVERAGE") || s.contains("FORCED")),
                "customer PoC steps omit internal tri-track jargon");
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
                "ZH report contains ## 关键发现");
        check(enforced.summary().contains(FindingBindings.EXEC_SECTION_ZH),
                "ZH report contains ## 执行摘要");
        check(enforced.summary().contains(FindingBindings.APPENDIX_SECTION_ZH),
                "ZH report contains ## 附录：技术细节");
        check(enforced.summary().contains("/home"), "section includes API route");
        check(enforced.summary().contains("PoC") || enforced.summary().contains("复现")
                        || enforced.summary().contains(FindingBindings.NO_POC_ZH),
                "section includes PoC marker");
        check(!enforced.summary().contains("## Vulnerabilities"),
                "locale-pure ZH must not retain ## Vulnerabilities header");
        check(!enforced.summary().contains(FindingBindings.LEGACY_SECTION_ZH),
                "legacy ## 漏洞相关 must be rewritten away");
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
        check(vulnIdx >= 0 && riskIdx > vulnIdx, "其他风险点 section follows 关键发现");
        check(md.contains("JWT") && md.indexOf("JWT") < riskIdx,
                "primary section mentions JWT material before 其他风险点");
        check(md.contains("风险提示（非主发现）") || md.contains("仅作风险提示"),
                "risk section labels non-primary risk notes");
        FindingBindings.EnforceResult enforced = FindingBindings.enforceReportSection(
                "# 审计报告\n\n## 漏洞相关\n\nthin\n", bindings, AiOutputLanguage.ZH_CN);
        check(enforced.summary().contains(FindingBindings.RISK_SECTION_ZH),
                "server enforce appends ## 其他风险点 when RISK_POINT bindings exist");
    }

    private static void deliverableTemplateHasCoverSummaryAppendix() {
        ApiDtos.EntryDto entry = entry("entry-ann-1", "GET", "/home");
        ApiDtos.FindingDto finding = finding(
                "finding-3", "强达路径风险材料", "entry-ann-1", "/home");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.startsWith(FindingBindings.TITLE_ZH), "starts with # 安全审计报告");
        check(md.contains("## 报告元信息") && md.contains("总体结论"), "cover/meta present");
        check(md.contains(FindingBindings.EXEC_SECTION_ZH)
                        && md.contains("发现数量（按严重度）")
                        && md.contains("验证与复现概况"),
                "executive summary present");
        check(md.contains("**风险等级**") && md.contains("**验证状态**")
                        && md.contains("**技术路径**") && md.contains("**简述**")
                        && md.contains("**复现步骤**"),
                "finding card uses deliverable fields");
        check(md.contains("仅静态信号（STATIC_INFERRED）"),
                "status uses human label with enum retained");
        check(md.contains("##### 证据摘要") || md.contains("#### 证据摘要"),
                "evidence digest is secondary heading");
        check(md.contains(FindingBindings.APPENDIX_SECTION_ZH)
                        && md.contains("poc.kind")
                        && md.contains("findingId"),
                "appendix holds technical fields");
        check(md.contains(FindingBindings.CHAIN_SECTION_ZH), "利用链 section present");
        check(md.indexOf(FindingBindings.SECTION_ZH)
                        < md.indexOf(FindingBindings.CHAIN_SECTION_ZH)
                        && md.indexOf(FindingBindings.CHAIN_SECTION_ZH)
                        < md.indexOf(FindingBindings.APPENDIX_SECTION_ZH),
                "利用链 follows key findings and precedes appendix");
        // 主文复现区不应直接暴露 provenance/kind 调试行
        int reproIdx = md.indexOf("**复现步骤**");
        int evidenceIdx = md.indexOf("证据摘要");
        int appendixIdx = md.indexOf(FindingBindings.APPENDIX_SECTION_ZH);
        String mainRepro = md.substring(reproIdx, evidenceIdx);
        check(!mainRepro.contains("provenance:") && !mainRepro.contains("kind="),
                "main reproduction block omits provenance/kind dump");
        check(appendixIdx > evidenceIdx, "appendix after evidence digest");
    }

    private static void unboundApiUsesHumanLabel() {
        ApiDtos.FindingDto finding = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a", "finding-unbound",
                "未绑定入口的敏感 sink", "info", ApiDtos.STATIC_INFERRED,
                "entry-unbound", "UNBOUND", "sink-x", "com.example.Sink#run", "none",
                List.of("none"), List.of("ev-1"), 1, 0.5, ApiDtos.MOCK, null,
                "hyp-u", "COMMAND");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(), List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "unbound binding assembled");
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains("入口未绑定"), "impact surface uses 入口未绑定");
        int appendixIdx = md.indexOf(FindingBindings.APPENDIX_SECTION_ZH);
        check(appendixIdx > 0, "appendix present for unbound finding");
        String mainBody = md.substring(0, appendixIdx);
        check(mainBody.contains("**入口**: 入口未绑定"), "main tech path entry is 入口未绑定");
        check(!mainBody.contains("UNKNOWN UNBOUND"), "main body avoids UNKNOWN UNBOUND dump");
        check(mainBody.contains("### 信息"), "info severity gets 信息 group");
    }

    private static void keyFindingsGroupedBySeverityWithTechPath() {
        ApiDtos.EntryDto highEntry = entry("entry-ann-10", "POST", "/admin/upload");
        ApiDtos.EntryDto medEntry = entry("entry-ann-11", "GET", "/api/profile");
        ApiDtos.FindingDto high = findingWithSeverity(
                "finding-high", "静态推断的任意文件上传信号", "entry-ann-10",
                "/admin/upload", "FILE_WRITE", "high");
        ApiDtos.FindingDto medium = findingWithSeverity(
                "finding-med", "静态推断的信息泄露信号", "entry-ann-11",
                "/api/profile", "INFO_LEAK", "medium");
        ApiDtos.PathRunDto run = pathRun(
                "pr-forced-2", "entry:POST:/admin/upload", 200, true,
                "plan:posture:entry-ann-10:forced_reachability");
        PathTrace trace = forcedTraceWithHops("pr-forced-2", "entry:entry-ann-10");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(medium, high), List.of(highEntry, medEntry), List.of(run),
                Map.of("pr-forced-2", trace), AiOutputLanguage.ZH_CN);
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        int highGroup = md.indexOf("### 高危");
        int medGroup = md.indexOf("### 中危");
        int keyIdx = md.indexOf(FindingBindings.SECTION_ZH);
        check(keyIdx >= 0 && highGroup > keyIdx, "关键发现 contains 高危 group");
        check(medGroup > highGroup, "中危 group follows 高危");
        check(md.contains("**技术路径**")
                        && md.contains("**入口**")
                        && md.contains("**中途代码逻辑**")
                        && md.contains("**底层触发位置**"),
                "finding card includes three-layer technical path");
        check(md.contains("CommonController#upload") || md.contains("FileService#store"),
                "mid logic / hops surfaced from PathTrace when available");
        FindingBindings.Binding highBinding = bindings.stream()
                .filter(b -> "finding-high".equals(b.findingId())).findFirst().orElseThrow();
        check(!highBinding.midLogic().isBlank()
                        && !highBinding.midLogic().equals(FindingBindings.NO_MID_LOGIC_ZH),
                "forced hops populate midLogic");
        check(md.contains("Sink#run") || md.contains("`sink`") || md.contains("底层触发位置"),
                "trigger location present");
    }

    private static void exploitChainSectionFromAuthPlusDangerousSink() {
        ApiDtos.EntryDto leave = entry("entry-ann-1", "GET", "/blade-desk/process/leave/detail");
        ApiDtos.EntryDto upload = entry("entry-ann-42", "POST", "/ueditor/upload");
        ApiDtos.FindingDto authGap = findingWithProperty(
                "finding-auth-gap", "静态推断的鉴权缺口信号", "entry-ann-1",
                "/blade-desk/process/leave/detail", "AUTH_GAP");
        ApiDtos.FindingDto fileWrite = findingWithProperty(
                "finding-upload", "静态推断的后台任意文件上传信号", "entry-ann-42",
                "/ueditor/upload", "FILE_WRITE");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(authGap, fileWrite), List.of(leave, upload), List.of(), Map.of(),
                AiOutputLanguage.ZH_CN);
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains(FindingBindings.CHAIN_SECTION_ZH), "利用链 section present");
        int chainIdx = md.indexOf(FindingBindings.CHAIN_SECTION_ZH);
        int appendixIdx = md.indexOf(FindingBindings.APPENDIX_SECTION_ZH);
        check(chainIdx > 0 && appendixIdx > chainIdx, "利用链 precedes appendix");
        String chainBody = md.substring(chainIdx, appendixIdx);
        check(chainBody.contains("【推断/候选】"), "chain lines marked as inferred/candidate");
        check(chainBody.contains("鉴权") || chainBody.contains("上传"),
                "chain mentions enabler and dangerous sink titles");
        check(!chainBody.contains("VERIFIED") || chainBody.contains("不等于已验证"),
                "chain honesty note does not claim VERIFIED");
        List<String> chains = FindingBindings.inferExploitChains(bindings, true);
        check(!chains.isEmpty(), "heuristic produces at least one candidate chain");
    }

    private static void maxBindingsKeepsHighImpactAndConfirmed() {
        java.util.ArrayList<ApiDtos.FindingDto> findings = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.EntryDto> entries = new java.util.ArrayList<>();
        // 前部塞满 AUTH_GAP，模拟 scan 原始顺序把高影响 finding 排在末尾。
        for (int i = 1; i <= FindingBindings.MAX_BINDINGS + 5; i++) {
            String entryId = "entry-gap-" + i;
            entries.add(entry(entryId, "GET", "/gap/" + i));
            findings.add(findingWithSeverity(
                    "finding-gap-" + i, "静态推断的鉴权缺口信号", entryId,
                    "/gap/" + i, "AUTH_GAP", "low"));
        }
        entries.add(entry("entry-shiro", "GET", "/login"));
        findings.add(findingWithSeverity(
                "finding-shiro-high", "静态推断的硬编码 RememberMe 密钥信号",
                "entry-shiro", "/login", "HARDCODED_REMEMBER_ME_CIPHER_KEY", "high"));
        findings.add(findingWithSeverity(
                "finding-cmd-med", "静态推断的命令执行信号",
                "entry-shiro", "/common/test-connection", "COMMAND", "medium"));
        findings.add(new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a", "finding-confirmed",
                "动态确认的危险 sink", "high", ApiDtos.DYNAMIC_CONFIRMED,
                "entry-shiro", "/common/test-connection", "sink-confirmed",
                "java.lang.Runtime#exec", "none", List.of("none"), List.of("ev-c"), 1, 0.9,
                ApiDtos.MOCK, null, "hyp-c", "COMMAND"));

        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                findings, entries, List.of(), Map.of(), AiOutputLanguage.ZH_CN);
        check(bindings.size() == FindingBindings.MAX_BINDINGS,
                "assemble still respects MAX_BINDINGS");
        java.util.Set<String> ids = bindings.stream()
                .map(FindingBindings.Binding::findingId)
                .collect(java.util.stream.Collectors.toSet());
        check(ids.contains("finding-shiro-high"),
                "MAX_BINDINGS must keep trailing high-severity RememberMe finding");
        check(ids.contains("finding-cmd-med"),
                "MAX_BINDINGS must keep COMMAND finding over AUTH_GAP noise");
        check(ids.contains("finding-confirmed"),
                "MAX_BINDINGS must keep DYNAMIC_CONFIRMED finding");
        FindingBindings.Binding confirmed = bindings.stream()
                .filter(b -> "finding-confirmed".equals(b.findingId())).findFirst().orElseThrow();
        check(ApiDtos.DYNAMIC_CONFIRMED.equals(confirmed.status()),
                "binding must not demote DYNAMIC_CONFIRMED");

        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains("RememberMe") || md.contains("硬编码"),
                "report markdown surfaces RememberMe after priority truncate");
        check(md.contains("已动态确认") || md.contains("DYNAMIC_CONFIRMED"),
                "report surfaces confirmed verification status");
        check(md.contains("高危"), "severity grouping still renders 高危");
    }

    private static void effectConfirmedBindingSurfacesDynamicConfirmed() {
        ApiDtos.EntryDto entry = entry("entry-ann-42", "POST", "/generator/check/code");
        ApiDtos.FindingDto finding = findingWithProperty(
                "finding-expr", "静态推断的表达式/模板注入信号",
                "entry-ann-42", "/generator/check/code", "EXPRESSION");
        ApiDtos.PathRunDto run = pathRun(
                "pr-expr", "entry:POST:/generator/check/code", 200, true,
                "plan:posture:entry-ann-42:forced_reachability");
        PathTrace trace = effectTrace(
                "pr-expr", "entry:POST:/generator/check/code",
                "EFFECT:EXPRESSION",
                "com.ql.util.express.ExpressRunner#execute");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(run),
                Map.of("pr-expr", trace), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "expression binding assembled");
        FindingBindings.Binding binding = bindings.get(0);
        check(ApiDtos.DYNAMIC_CONFIRMED.equals(binding.status()),
                "H4 EXPRESSION effect must surface DYNAMIC_CONFIRMED in REPORT bindings"
                        + " even when finding row is still STATIC_INFERRED");
        check(binding.title().contains("已动态确认") || binding.title().contains("确认"),
                "confirmed binding rewrites title away from 静态推断");
        check(binding.pathRunRefs().contains("pr-expr"), "confirmed binding keeps pathRunRefs");
        check("DYNAMIC_CONFIRMED_POC".equals(binding.poc().kind()),
                "confirmed binding emits DYNAMIC_CONFIRMED_POC");
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains("已动态确认") || md.contains("DYNAMIC_CONFIRMED"),
                "report markdown counts/surfaces confirmed status");
        check(!md.contains("仅静态信号：1") && !md.contains("仅静态信号: 1"),
                "executive summary must not claim all-static when a finding is confirmed");
    }

    private static void incidentalDeserialDoesNotConfirmUnrelatedFinding() {
        ApiDtos.EntryDto entry = entry("entry-ann-1", "GET", "/ueditor/upload");
        ApiDtos.FindingDto authGap = findingWithProperty(
                "finding-auth", "静态推断的鉴权缺口信号",
                "entry-ann-1", "/ueditor/upload", "AUTH_GAP");
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-deserial-noise", "scan-a",
                "entry:GET:/ueditor/upload", "ADMIN", "attempt-1",
                "plan:posture:entry-ann-1:forced_reachability", "GET",
                "text/plain", "GET /ueditor/upload track=ADMIN", "HTTP_OBSERVED",
                200, true, true, List.of(), "HTTP_OBSERVED",
                ApiDtos.DYNAMIC_CONFIRMED, List.of("ev-noise"), "MOCK", "");
        PathTrace trace = effectTrace(
                "pr-deserial-noise", "entry:GET:/ueditor/upload",
                "EFFECT:DESERIALIZATION",
                "org.apache.shiro.mgt.AbstractRememberMeManager#getRememberedPrincipals");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(authGap), List.of(entry), List.of(run),
                Map.of("pr-deserial-noise", trace), AiOutputLanguage.ZH_CN);
        FindingBindings.Binding authBinding = bindings.stream()
                .filter(b -> "finding-auth".equals(b.findingId())).findFirst().orElse(null);
        check(authBinding != null, "auth-gap binding assembled");
        check(ApiDtos.STATIC_INFERRED.equals(authBinding.status()),
                "incidental Shiro DESERIAL PathRun CONFIRMED must not elevate AUTH_GAP finding");
        check(bindings.stream().anyMatch(b ->
                        "DESERIALIZATION".equals(b.securityProperty())
                                && ApiDtos.DYNAMIC_CONFIRMED.equals(b.status())),
                "Shiro DESERIAL must surface as orphan/channel binding, not be swallowed by AUTH_GAP");
    }

    private static void maxBindingsPrefersForcedMaterialsOverStaticAuthGap() {
        java.util.ArrayList<ApiDtos.FindingDto> findings = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.EntryDto> entries = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.PathRunDto> runs = new java.util.ArrayList<>();
        java.util.HashMap<String, PathTrace> traces = new java.util.HashMap<>();
        for (int i = 1; i <= FindingBindings.MAX_BINDINGS + 3; i++) {
            String entryId = "entry-gap-" + i;
            String route = "/gap/" + i;
            entries.add(entry(entryId, "GET", route));
            findings.add(findingWithSeverity(
                    "finding-gap-" + i, "静态推断的鉴权缺口信号", entryId,
                    route, "AUTH_GAP", "low"));
        }
        entries.add(entry("entry-forced", "GET", "/blade-desk/dashboard/activities"));
        findings.add(findingWithSeverity(
                "finding-forced-auth", "静态推断的鉴权缺口信号", "entry-forced",
                "/blade-desk/dashboard/activities", "AUTH_GAP", "low"));
        ApiDtos.PathRunDto forced = pathRun(
                "pr-forced-dash", "entry:GET:/blade-desk/dashboard/activities",
                200, true, "plan:posture:entry-forced:forced_reachability");
        runs.add(forced);
        traces.put("pr-forced-dash", forcedTraceWithHops(
                "pr-forced-dash", "entry:GET:/blade-desk/dashboard/activities"));
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                findings, entries, runs, traces, AiOutputLanguage.ZH_CN);
        java.util.Set<String> ids = bindings.stream()
                .map(FindingBindings.Binding::findingId)
                .collect(java.util.stream.Collectors.toSet());
        check(ids.contains("finding-forced-auth"),
                "MAX_BINDINGS must keep AUTH_GAP that has FORCED PathRun materials");
        FindingBindings.Binding forcedBinding = bindings.stream()
                .filter(b -> "finding-forced-auth".equals(b.findingId())).findFirst().orElseThrow();
        check(forcedBinding.pathRunRefs().contains("pr-forced-dash"),
                "forced AUTH_GAP keeps pathRunRefs after truncate");
        check(forcedBinding.title().contains("强达") || forcedBinding.poc().steps().stream()
                        .anyMatch(s -> s.contains("授权沙箱") || s.contains("HTTP")),
                "forced materials surface in title or PoC");
    }

    private static void orphanSpelEffectBecomesConfirmedBinding() {
        ApiDtos.EntryDto entry = entry("entry-sms", "POST", "/blade-resource/sms/enable");
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-spel", "scan-a",
                "entry:POST:/blade-resource/sms/enable", "UNAUTH", "attempt-1",
                "plan:posture:entry-sms:forced_reachability", "POST", "application/json",
                "POST /blade-resource/sms/enable track=UNAUTH", "AUTH_CHALLENGE",
                401, true, null, List.of(), "AUTH_CHALLENGE",
                ApiDtos.DYNAMIC_CONFIRMED, List.of("ev-spel"), "MOCK", "");
        PathTrace trace = effectTrace(
                "pr-spel", "entry:POST:/blade-resource/sms/enable",
                "EFFECT:EXPRESSION",
                "org.springframework.expression.spel.standard.SpelExpression#getValue");
        java.util.ArrayList<ApiDtos.FindingDto> noise = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.EntryDto> entries = new java.util.ArrayList<>();
        entries.add(entry);
        for (int i = 1; i <= FindingBindings.MAX_BINDINGS; i++) {
            String entryId = "entry-noise-" + i;
            entries.add(entry(entryId, "GET", "/noise/" + i));
            noise.add(findingWithSeverity(
                    "finding-noise-" + i, "静态推断的鉴权缺口信号", entryId,
                    "/noise/" + i, "AUTH_GAP", "low"));
        }
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                noise, entries, List.of(run),
                Map.of("pr-spel", trace), AiOutputLanguage.ZH_CN);
        check(bindings.stream().anyMatch(b ->
                        ApiDtos.DYNAMIC_CONFIRMED.equals(b.status())
                                && "EXPRESSION".equals(b.securityProperty())),
                "orphan EXPRESSION must win a MAX_BINDINGS slot over static AUTH_GAP noise");
        FindingBindings.Binding orphan = bindings.stream()
                .filter(b -> "EXPRESSION".equals(b.securityProperty())).findFirst().orElseThrow();
        check(orphan.title().contains("SpEL") || orphan.title().contains("表达式"),
                "orphan title names SpEL/表达式");
        check(orphan.pathRunRefs().contains("pr-spel"), "orphan keeps pathRunRefs");
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains("已动态确认") || md.contains("DYNAMIC_CONFIRMED"),
                "report surfaces orphan SpEL as confirmed, not all-static");
    }

    private static void orphanSpelNotBlockedByAuthGapOnSameEntry() {
        ApiDtos.EntryDto entry = entry("entry-sms", "POST", "/blade-resource/sms/enable");
        ApiDtos.FindingDto authGap = findingWithProperty(
                "finding-auth-sms", "静态推断的鉴权缺口信号",
                "entry-sms", "/blade-resource/sms/enable", "AUTH_GAP");
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-spel-auth", "scan-a",
                "entry:POST:/blade-resource/sms/enable", "UNAUTH", "attempt-1",
                "plan:posture:entry-sms:forced_reachability", "POST", "application/json",
                "POST /blade-resource/sms/enable track=UNAUTH", "AUTH_CHALLENGE",
                401, true, null, List.of(), "AUTH_CHALLENGE",
                ApiDtos.DYNAMIC_CONFIRMED, List.of("ev-spel-auth"), "MOCK", "");
        PathTrace trace = effectTrace(
                "pr-spel-auth", "entry:POST:/blade-resource/sms/enable",
                "EFFECT:EXPRESSION",
                "org.springframework.expression.spel.standard.SpelExpression#getValue");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(authGap), List.of(entry), List.of(run),
                Map.of("pr-spel-auth", trace), AiOutputLanguage.ZH_CN);
        check(bindings.stream().anyMatch(b ->
                        ApiDtos.DYNAMIC_CONFIRMED.equals(b.status())
                                && "EXPRESSION".equals(b.securityProperty())),
                "AUTH_GAP on same entry must not swallow orphan EXPRESSION effect");
        check(bindings.stream().anyMatch(b -> "finding-auth-sms".equals(b.findingId())),
                "AUTH_GAP finding remains alongside orphan SpEL");
    }

    private static void orphanCapLeavesRoomForHighImpactFindings() {
        java.util.ArrayList<ApiDtos.FindingDto> findings = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.EntryDto> entries = new java.util.ArrayList<>();
        java.util.ArrayList<ApiDtos.PathRunDto> runs = new java.util.ArrayList<>();
        java.util.LinkedHashMap<String, PathTrace> traces = new java.util.LinkedHashMap<>();
        for (int i = 1; i <= 40; i++) {
            String entryId = "entry-spel-" + i;
            String route = "/blade-resource/sms/orphan/" + i;
            entries.add(entry(entryId, "POST", route));
            String pr = "pr-orphan-" + i;
            runs.add(new ApiDtos.PathRunDto(
                    ApiDtos.SCHEMA_VERSION, pr, "scan-a",
                    "entry:POST:" + route, "UNAUTH", "attempt-1",
                    "plan:posture:" + entryId + ":forced_reachability", "POST", "application/json",
                    "POST " + route, "AUTH_CHALLENGE",
                    401, true, null, List.of(), "AUTH_CHALLENGE",
                    ApiDtos.DYNAMIC_CONFIRMED, List.of("ev-" + pr), "MOCK", ""));
            traces.put(pr, effectTrace(pr, "entry:POST:" + route, "EFFECT:EXPRESSION",
                    "org.springframework.expression.spel.standard.SpelExpression#getValue"));
        }
        entries.add(entry("entry-jwt", "GET", "/blade-auth/oauth/token"));
        findings.add(findingWithSeverity(
                "finding-jwt-keep", "静态推断的硬编码/默认 JWT 签名密钥信号",
                "entry-jwt", "/blade-auth/oauth/token", "HARDCODED_JWT_SIGN_KEY", "high"));
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                findings, entries, runs, traces, AiOutputLanguage.ZH_CN);
        long orphanConfirmed = bindings.stream()
                .filter(b -> "EXPRESSION".equals(b.securityProperty())
                        && ApiDtos.DYNAMIC_CONFIRMED.equals(b.status()))
                .count();
        check(orphanConfirmed <= FindingBindings.MAX_ORPHAN_BINDINGS,
                "orphan EXPRESSION bindings must respect MAX_ORPHAN_BINDINGS");
        check(bindings.stream().anyMatch(b -> "finding-jwt-keep".equals(b.findingId())),
                "JWT high-impact finding must survive orphan flood");
    }

    private static void executiveSummarySeparatesForcedFromPureStatic() {
        ApiDtos.EntryDto forcedEntry = entry("entry-forced", "GET", "/blade-desk/notice/list");
        ApiDtos.EntryDto staticEntry = entry("entry-static", "GET", "/blade-desk/notice/detail");
        ApiDtos.FindingDto forcedFinding = findingWithProperty(
                "finding-forced", "静态推断的鉴权缺口信号",
                "entry-forced", "/blade-desk/notice/list", "AUTH_GAP");
        ApiDtos.FindingDto staticFinding = findingWithProperty(
                "finding-static", "静态推断的鉴权缺口信号",
                "entry-static", "/blade-desk/notice/detail", "AUTH_GAP");
        ApiDtos.PathRunDto forced = pathRun(
                "pr-forced-exec", "entry:GET:/blade-desk/notice/list", 200, true,
                "plan:posture:entry-forced:forced_reachability");
        PathTrace trace = forcedTraceWithHops(
                "pr-forced-exec", "entry:GET:/blade-desk/notice/list");
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(forcedFinding, staticFinding),
                List.of(forcedEntry, staticEntry),
                List.of(forced),
                Map.of("pr-forced-exec", trace),
                AiOutputLanguage.ZH_CN);
        String md = FindingBindings.renderMarkdownSection(bindings, AiOutputLanguage.ZH_CN);
        check(md.contains("含运行时路径材料"),
                "executive summary must count forced materials separately from pure static");
        check(md.contains("仅静态信号"), "executive summary retains pure-static bucket");
        check(md.contains("强达") || md.contains("路径观测"),
                "overall conclusion must not claim pure-static when forced materials exist");
    }

    private static void rememberMeDeserialOrphansCollapse() {
        java.util.ArrayList<ApiDtos.PathRunDto> runs = new java.util.ArrayList<>();
        java.util.LinkedHashMap<String, PathTrace> traces = new java.util.LinkedHashMap<>();
        for (int i = 0; i < 8; i++) {
            String route = "/sys/menu/item-" + i;
            String pr = "pr-rm-" + i;
            runs.add(new ApiDtos.PathRunDto(
                    ApiDtos.SCHEMA_VERSION, pr, "scan-a",
                    "entry:GET:" + route, "UNAUTH", "attempt-1",
                    "plan:posture:forced_reachability", "GET", "application/json",
                    "GET " + route + " cookie=rememberMe=xxx", "AUTH_CHALLENGE",
                    302, true, null, List.of(), "AUTH_CHALLENGE",
                    ApiDtos.DYNAMIC_CONFIRMED, List.of("ev-" + pr), "MOCK", ""));
            traces.put(pr, effectTrace(pr, "entry:GET:" + route, "EFFECT:DESERIALIZATION",
                    "org.apache.shiro.mgt.AbstractRememberMeManager#getRememberedSerializedIdentity"));
        }
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(), List.of(), runs, traces, AiOutputLanguage.ZH_CN);
        long deserial = bindings.stream()
                .filter(b -> "DESERIALIZATION".equals(b.securityProperty()))
                .count();
        check(deserial == 1, "RememberMe DESERIAL orphans must collapse to one binding");
        check(bindings.get(0).title().contains("RememberMe") || bindings.get(0).title().contains("反序列化"),
                "collapsed orphan titles RememberMe/反序列化 channel");
    }

    private static void nullEntryHitForcedFillsMidLogicFromHops() {
        ApiDtos.EntryDto entry = entry("entry-ann-8", "POST", "/blade-flow/model/deploy");
        ApiDtos.FindingDto finding = findingWithProperty(
                "finding-bpmn", "静态推断的BPMN/流程部署信号",
                "entry-ann-8", "/blade-flow/model/deploy", "BPMN_DEPLOY");
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-bpmn", "scan-a",
                "entry:POST:/blade-flow/model/deploy", "ADMIN", "attempt-1",
                "plan:posture:entry-ann-8:forced_reachability", "POST", "application/json",
                "POST /blade-flow/model/deploy", "DEPENDENCY_MOCK_GAP",
                500, null, null, List.of(), "DEPENDENCY_MOCK_GAP",
                ApiDtos.UNREACHED, List.of("ev-bpmn"), "MOCK", "");
        List<TraceEvent> events = List.of(
                new TraceEvent(1, TraceEventKind.ENTRY_HIT, "entry",
                        "entry:POST:/blade-flow/model/deploy", "", false, Map.of(), ""),
                new TraceEvent(2, TraceEventKind.METHOD_HOP, "hop",
                        "org.springblade.flow.engine.service.impl.FlowEngineServiceImpl#deployModel",
                        "", false, Map.of(), ""),
                new TraceEvent(3, TraceEventKind.METHOD_HOP, "hop",
                        "org.flowable.engine.RepositoryService#createDeployment",
                        "", false, Map.of(), ""));
        PathTrace trace = new PathTrace(
                PathTrace.SCHEMA_VERSION, "pathtrace:pr-bpmn", "pr-bpmn",
                "probe-1", "plan:posture:entry-ann-8:forced_reachability", "traceplan-1",
                "entry:POST:/blade-flow/model/deploy", "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:TokenInterceptor")),
                "world-1", "corr-1", 1, events, List.of(),
                TraceExitReason.DEPENDENCY_UNAVAILABLE,
                "org.flowable.engine.RepositoryService#createDeployment",
                List.of(), false);
        List<FindingBindings.Binding> bindings = FindingBindings.assemble(
                List.of(finding), List.of(entry), List.of(run),
                Map.of("pr-bpmn", trace), AiOutputLanguage.ZH_CN);
        check(bindings.size() == 1, "bpmn binding assembled");
        FindingBindings.Binding binding = bindings.get(0);
        check(binding.pathRunRefs().contains("pr-bpmn"), "bpmn 500 attaches pathRun via Trace ENTRY_HIT");
        check(!FindingBindings.NO_MID_LOGIC_ZH.equals(binding.midLogic()),
                "midLogic must not stay empty when METHOD_HOP exists");
        check(binding.midLogic().contains("FlowEngineServiceImpl")
                        || binding.midLogic().contains("RepositoryService")
                        || binding.midLogic().contains("deployModel"),
                "midLogic includes business hop subjects");
    }

    private static PathTrace effectTrace(
            String pathRunId, String entryRef, String effectToken, String subject) {
        List<TraceEvent> events = List.of(
                new TraceEvent(1, TraceEventKind.ENTRY_HIT, "entry", entryRef,
                        "", false, Map.of(), ""),
                new TraceEvent(2, TraceEventKind.EFFECT_TRIGGERED, effectToken + " at " + subject,
                        subject, effectToken, false, Map.of(), ""));
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
                subject,
                List.of(effectToken, subject),
                false);
    }

    private static void languageInstructionLocalePure() throws Exception {
        String zh = AiPromptLanguage.languageInstruction(AiOutputLanguage.ZH_CN);
        String en = AiPromptLanguage.languageInstruction(AiOutputLanguage.EN);
        check(zh.contains("locale-pure") || zh.contains("不得夹杂"),
                "ZH languageInstruction requires locale purity");
        check(zh.contains("## Vulnerabilities") || zh.contains("## Key Findings"),
                "ZH forbids English findings headers");
        check(en.contains("locale-pure") || en.contains("must not mix"),
                "EN languageInstruction requires locale purity");
        check(en.contains("## 关键发现") || en.contains("## 漏洞相关"),
                "EN forbids Chinese findings headers");

        String reportZh = AiRolePrompts.roleInstruction(
                com.aq.jvmsentinel.provider.AgentRole.REPORT_GENERATION, AiOutputLanguage.ZH_CN);
        check(reportZh.contains("FINDING_BINDINGS_FACTS") || reportZh.contains("findingBindings"),
                "ZH REPORT consumes FINDING_BINDINGS_FACTS / findingBindings");
        check(reportZh.contains("locale-pure") || reportZh.contains("禁止英文专章"),
                "ZH REPORT requires locale-pure Chinese");
        check(reportZh.contains("【必填章节】") && reportZh.contains("【Markdown 骨架"),
                "ZH REPORT prompt includes required-section outline and Markdown skeleton");
        check(reportZh.contains("本轮未形成可复现 PoC") && reportZh.contains("INSTRUMENTATION_REACHABILITY"),
                "ZH REPORT template requires honest PoC / FORCED provenance");
        check(reportZh.contains("## 关键发现") && reportZh.contains("## 其他风险点")
                        && reportZh.contains("reportRole=RISK_POINT"),
                "ZH REPORT template requires 关键发现 / 其他风险点 ordering gate");
        check(reportZh.contains("## 利用链") && reportZh.contains("本轮未识别可组合利用链"),
                "ZH REPORT requires 利用链 section with honest empty state");
        check(reportZh.contains("高危") && reportZh.contains("中途代码逻辑")
                        && reportZh.contains("底层触发位置"),
                "ZH REPORT requires severity groups and three-layer tech path");
        check(reportZh.contains("## 附录：技术细节"), "ZH REPORT requires technical appendix");
        check(reportZh.contains("ADR-0004"), "ZH REPORT keeps ADR-0004 posture honesty");
        check(reportZh.contains("禁止旧模板") && reportZh.contains("## 关键发现"),
                "ZH REPORT forbids legacy chapter and uses 关键发现");
        check(!reportZh.contains("2. ## 漏洞相关"),
                "ZH REPORT required-section list must not lead with legacy 漏洞相关");
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
        return findingWithSeverity(id, title, entryId, route, securityProperty, "high");
    }

    private static ApiDtos.FindingDto findingWithSeverity(
            String id, String title, String entryId, String route,
            String securityProperty, String severity) {
        String sink = "FILE_WRITE".equals(securityProperty)
                ? "com.kalvin.kvf.common.service.FileService#store"
                : "com.example.Sink#run";
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a", id, title, severity,
                ApiDtos.STATIC_INFERRED, entryId, route, "sink-1", sink, "none",
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
