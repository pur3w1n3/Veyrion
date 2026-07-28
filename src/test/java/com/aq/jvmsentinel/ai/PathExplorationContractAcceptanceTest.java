package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
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
 * P0-11: PATH_EXPLORATION sandbox_probe allowlist / prompt / schema contract unity.
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
        Method roleInstruction = AiJobOrchestrator.class.getDeclaredMethod(
                "roleInstruction", AgentRole.class, AiOutputLanguage.class);
        roleInstruction.setAccessible(true);
        String zh = (String) roleInstruction.invoke(null, AgentRole.PATH_EXPLORATION, AiOutputLanguage.ZH_CN);
        String en = (String) roleInstruction.invoke(null, AgentRole.PATH_EXPLORATION, AiOutputLanguage.EN);
        check(zh.contains("sandbox_probe"), "ZH PATH roleInstruction mentions sandbox_probe");
        check(zh.contains("track") && zh.contains("objective") && zh.contains("coverageGapRef"),
                "ZH PATH roleInstruction requires track/objective/coverageGapRef");
        check(zh.contains("命令") || zh.contains("镜像") || zh.contains("挂载"),
                "ZH PATH roleInstruction forbids command/image/mount");
        check(en.toLowerCase(Locale.ROOT).contains("sandbox_probe"),
                "EN PATH roleInstruction mentions sandbox_probe");
        check(en.contains("track") && en.contains("objective") && en.contains("coverageGapRef"),
                "EN PATH roleInstruction requires track/objective/coverageGapRef");
        check(en.toLowerCase(Locale.ROOT).contains("command")
                        && en.toLowerCase(Locale.ROOT).contains("image")
                        && en.toLowerCase(Locale.ROOT).contains("budget"),
                "EN PATH roleInstruction forbids command/image/budget");

        Field systemPrompt = AiJobOrchestrator.class.getDeclaredField("SYSTEM_PROMPT");
        systemPrompt.setAccessible(true);
        String system = (String) systemPrompt.get(null);
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
