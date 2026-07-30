package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.prompt.AiRolePrompts;
import com.aq.jvmsentinel.ai.prompt.AiSystemPrompt;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-11：PATH_EXPLORATION sandbox_probe allowlist / prompt / schema 合同一致性。
 */
public final class PathExplorationContractAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ToolExecutionContext.Scope SCOPE =
            new ToolExecutionContext.Scope("local", "project-path-contract");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        pathAllowlistIncludesSandboxProbe();
        pathMissingFieldsRejected();
        sandboxProbeDescriptionRequiresGapFields();
        pathRoleAndSystemPromptsUnified();
        System.out.println("PathExplorationContractAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void pathAllowlistIncludesSandboxProbe() {
        ToolExecutionContext.Budget budget = new ToolExecutionContext.Budget(
                8, 65_536, 16, 65_536, Instant.now().plusSeconds(60));
        ToolExecutionContext context = ToolExecutionContext.bind(
                SCOPE, "op-1", "job-path-allow", AgentRole.PATH_EXPLORATION, budget);
        check(context.allowedTools().contains("sandbox_probe"),
                "PATH_EXPLORATION allowlist includes sandbox_probe");
        check(context.allowedTools().contains("code_query"),
                "PATH_EXPLORATION allowlist retains code_query");
    }

    private static void pathMissingFieldsRejected() throws Exception {
        FakeSource source = new FakeSource(List.of("tp-gap-1"));
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = ToolExecutionContext.bind(
                SCOPE, "op-1", "job-path-fields", AgentRole.PATH_EXPLORATION,
                new ToolExecutionContext.Budget(8, 65_536, 16, 65_536, Instant.now().plusSeconds(60)));

        ObjectNode missingTrack = JSON.createObjectNode();
        missingTrack.put("entrypointRef", "entry:entry-1");
        missingTrack.put("objective", "close coverage gap");
        missingTrack.put("coverageGapRef", "tp-gap-1");
        ToolResult deniedTrack = registry.execute(
                new ToolCall(1, "call-miss-track", "sandbox_probe", missingTrack), context);
        check(deniedTrack.status() == ToolStatus.INVALID_ARGUMENTS, "PATH missing track denied");
        check("PATH_PROBE_FIELDS_REQUIRED".equals(deniedTrack.errorCode()),
                "PATH_PROBE_FIELDS_REQUIRED for missing track");

        ObjectNode missingGap = JSON.createObjectNode();
        missingGap.put("entrypointRef", "entry:entry-1");
        missingGap.put("track", "UNAUTH");
        missingGap.put("objective", "close coverage gap");
        ToolResult deniedGap = registry.execute(
                new ToolCall(1, "call-miss-gap", "sandbox_probe", missingGap), context);
        check(deniedGap.status() == ToolStatus.INVALID_ARGUMENTS, "PATH missing coverageGapRef denied");
        check("COVERAGE_GAP_REQUIRED".equals(deniedGap.errorCode()),
                "COVERAGE_GAP_REQUIRED when gaps present");
    }

    private static void sandboxProbeDescriptionRequiresGapFields() {
        AiToolRegistry registry = new AiToolRegistry(new FakeSource(List.of()));
        String description = registry.definitionsFor(AgentRole.PATH_EXPLORATION).stream()
                .filter(def -> "sandbox_probe".equals(def.name()))
                .map(AiToolRegistry.ToolDefinition::description)
                .findFirst()
                .orElse("");
        String lower = description.toLowerCase(Locale.ROOT);
        check(!description.isBlank(), "PATH definitions expose sandbox_probe");
        check(lower.contains("track"), "sandbox_probe description mentions track");
        check(lower.contains("objective"), "sandbox_probe description mentions objective");
        check(lower.contains("coveragegapref"), "sandbox_probe description mentions coverageGapRef");
        check(lower.contains("expectedsignal") && lower.contains("stopcondition"),
                "sandbox_probe description mentions expectedSignal/stopCondition labels");
        check(lower.contains("command") && lower.contains("image") && lower.contains("mount")
                        && lower.contains("network") && lower.contains("uid") && lower.contains("budget"),
                "sandbox_probe description forbids command/image/mount/network/UID/budget");
        check(lower.contains("coverage gap") || lower.contains("coveragegap"),
                "sandbox_probe description scopes PATH to coverage gap");
    }

    private static void pathRoleAndSystemPromptsUnified() throws Exception {
        String zh = AiRolePrompts.roleInstruction(AgentRole.PATH_EXPLORATION, AiOutputLanguage.ZH_CN);
        String en = AiRolePrompts.roleInstruction(AgentRole.PATH_EXPLORATION, AiOutputLanguage.EN);
        check(zh.contains("sandbox_probe"), "ZH PATH roleInstruction mentions sandbox_probe");
        check(zh.contains("track") && zh.contains("objective") && zh.contains("coverageGapRef"),
                "ZH PATH roleInstruction requires track/objective/coverageGapRef");
        check(zh.contains("命令") || zh.contains("镜像") || zh.contains("挂载"),
                "ZH PATH roleInstruction forbids command/image/mount");
        check(zh.contains("有运行时路径材料") && zh.contains("无运行时确认")
                        && zh.contains("INSTRUMENTATION_REACHABILITY"),
                "ZH PATH FORCED 2xx+ENTRY_HIT is runtime path material; forbids 无运行时确认");
        check(zh.contains("findingBindings") && zh.contains("api:{method,route,entryRef}")
                        && zh.contains("poc:{kind,steps[],provenance}")
                        && zh.contains("STATIC_INFERRED"),
                "ZH PATH requires findingBindings with API+PoC for REPORT");
        check(zh.contains("FORCED") && zh.contains("ADR-0004")
                        && zh.contains("DYNAMIC_CONFIRMED") && zh.contains("VERIFIED"),
                "ZH PATH forbids FORCED-only DYNAMIC_CONFIRMED/VERIFIED (ADR-0004)");
        check(en.toLowerCase(Locale.ROOT).contains("sandbox_probe"),
                "EN PATH roleInstruction mentions sandbox_probe");
        check(en.contains("track") && en.contains("objective") && en.contains("coverageGapRef"),
                "EN PATH roleInstruction requires track/objective/coverageGapRef");
        check(en.toLowerCase(Locale.ROOT).contains("command")
                        && en.toLowerCase(Locale.ROOT).contains("image")
                        && en.toLowerCase(Locale.ROOT).contains("budget"),
                "EN PATH roleInstruction forbids command/image/budget");
        check(en.contains("runtime path material")
                        && en.contains("no runtime confirmation")
                        && en.contains("INSTRUMENTATION_REACHABILITY"),
                "EN PATH FORCED 2xx+ENTRY_HIT is runtime path material");
        check(en.contains("findingBindings") && en.contains("api:{method,route,entryRef}")
                        && en.contains("poc:{kind,steps[],provenance}")
                        && en.contains("STATIC_INFERRED"),
                "EN PATH requires findingBindings with API+PoC for REPORT");
        check(en.contains("FORCED") && en.contains("ADR-0004")
                        && en.contains("DYNAMIC_CONFIRMED") && en.contains("VERIFIED"),
                "EN PATH forbids FORCED-only DYNAMIC_CONFIRMED/VERIFIED (ADR-0004)");

        String reportZh = AiRolePrompts.roleInstruction(
                AgentRole.REPORT_GENERATION, AiOutputLanguage.ZH_CN);
        String reportEn = AiRolePrompts.roleInstruction(
                AgentRole.REPORT_GENERATION, AiOutputLanguage.EN);
        check(reportZh.contains("## 漏洞相关") && reportZh.contains("findingBindings"),
                "ZH REPORT Markdown leads with ## 漏洞相关 from PATH findingBindings");
        check(reportZh.contains("FINDING_BINDINGS_FACTS") || reportZh.contains("findingBindings"),
                "ZH REPORT consumes FINDING_BINDINGS_FACTS");
        check(reportZh.contains("locale-pure") || reportZh.contains("禁止英文专章"),
                "ZH REPORT requires locale-pure Chinese");
        check(reportZh.contains("ADR-0004") && reportZh.contains("FORCED"),
                "ZH REPORT forbids FORCED-only elevation (ADR-0004)");
        check(reportZh.contains("【必填章节】") && reportZh.contains("【选填章节】")
                        && reportZh.contains("【Markdown 骨架"),
                "ZH REPORT has required/optional outline + Markdown skeleton");
        check(reportEn.contains("## Vulnerabilities") && reportEn.contains("findingBindings"),
                "EN REPORT Markdown leads with ## Vulnerabilities from PATH findingBindings");
        check(reportEn.contains("FINDING_BINDINGS_FACTS") || reportEn.contains("findingBindings"),
                "EN REPORT consumes FINDING_BINDINGS_FACTS");
        check(reportEn.contains("locale-pure") || reportEn.contains("must not mix"),
                "EN REPORT requires locale-pure English");
        check(reportEn.contains("ADR-0004") && reportEn.contains("FORCED"),
                "EN REPORT forbids FORCED-only elevation (ADR-0004)");
        check(reportEn.contains("[Required sections]") && reportEn.contains("[Optional sections]")
                        && reportEn.contains("[Markdown skeleton"),
                "EN REPORT has required/optional outline + Markdown skeleton");

        String system = AiSystemPrompt.SYSTEM_PROMPT;
        check(system.contains("PATH_EXPLORATION"), "SYSTEM_PROMPT mentions PATH_EXPLORATION");
        check(system.contains("sandbox_probe"), "SYSTEM_PROMPT mentions sandbox_probe");
        check(system.contains("coverageGapRef"), "SYSTEM_PROMPT mentions coverageGapRef");
        check(system.toLowerCase(Locale.ROOT).contains("image"),
                "SYSTEM_PROMPT forbids choosing image");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static final class FakeSource implements ToolDataSource {
        private final List<String> gaps;

        FakeSource(List<String> gaps) {
            this.gaps = List.copyOf(gaps);
        }

        @Override
        public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind, String query, int limit) {
            return List.of();
        }

        @Override
        public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
            return Optional.empty();
        }

        @Override
        public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
            ObjectNode value = JSON.createObjectNode();
            value.put("entrypoint", "app.Controller");
            value.put("route", "/api/x");
            value.put("method", "GET");
            return Optional.of(new FactRecord(scope, "entry:entry-1", value));
        }

        @Override
        public Optional<FactRecord> requestSandboxProbe(
                ToolExecutionContext.Scope scope, String principalId, String jobId, String toolCallId,
                String entrypointRef, List<String> candidateInputs, int maxRequests,
                String techniqueId, String authorizationHeader, String bladeAuthHeader,
                String experimentPlanId) {
            ObjectNode value = JSON.createObjectNode();
            value.put("state", "COMPLETED");
            value.put("pathRunCount", 1);
            value.put("lifecycle", "COMPLETED");
            return Optional.of(new FactRecord(scope, "sandbox-probe:" + toolCallId, value));
        }

        @Override
        public List<String> coverageGapIds(ToolExecutionContext.Scope scope) {
            return gaps;
        }
    }
}
