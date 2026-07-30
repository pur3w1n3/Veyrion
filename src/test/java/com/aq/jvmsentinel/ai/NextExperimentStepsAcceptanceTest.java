package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.model.NextExperimentStep;

import java.util.Set;

/**
 * P1-05：PATH/TRIAGE nextExperiments 须基于 PathRun 且 sandbox_probe 可消费。
 */
public final class NextExperimentStepsAcceptanceTest {
    public static void main(String[] args) {
        rejectsAuthGapNarrativeWithoutPathRun();
        acceptsPathRunGroundedStep();
        rejectsUnknownEntry();
        rejectsStaticOnlyBypassClaim();
        System.out.println("NextExperimentStepsAcceptanceTest: PASS");
    }

    private static void rejectsAuthGapNarrativeWithoutPathRun() {
        String conclusion = """
                {"schemaVersion":1,"classification":"INFERENCE","summary":"auth gaps everywhere",
                 "nextExperiments":[{"entryRef":"entry:e1","objective":"AUTH_GAP review only","track":"UNAUTH"}]}
                """;
        NextExperimentSteps.ParseResult parsed = NextExperimentSteps.parseAndValidate(
                conclusion, Set.of("entry:e1"), Set.of("pathrun-1"));
        check(parsed.steps().isEmpty(), "AUTH_GAP-only without pathRunRefs rejected");
        check(parsed.rejected().stream().anyMatch(msg -> msg.contains("AUTH_GAP")),
                "reject reason mentions AUTH_GAP");
    }

    private static void acceptsPathRunGroundedStep() {
        String conclusion = """
                {"nextExperiments":[{
                  "entryRef":"entry:e1",
                  "objective":"Replay UNAUTH vs ADMIN contrast on shared session cookie",
                  "track":"ADMIN",
                  "techniqueId":"MISSING_AUTH",
                  "candidateInputs":["q=1"],
                  "pathRunRefs":["pathrun-1"],
                  "rationale":"shared PathRun evidence"
                }]}
                """;
        NextExperimentSteps.ParseResult parsed = NextExperimentSteps.parseAndValidate(
                conclusion, Set.of("entry:e1"), Set.of("pathrun-1"));
        check(parsed.steps().size() == 1, "accepts PathRun-grounded step");
        NextExperimentStep step = parsed.steps().get(0);
        check("entry:e1".equals(step.entryRef()), "entryRef preserved");
        check(step.pathRunRefs().contains("pathrun-1"), "pathRunRefs preserved");
        check("MISSING_AUTH".equals(step.techniqueId()), "techniqueId preserved");
        String prompt = NextExperimentSteps.formatForPrompt(parsed.steps(), true);
        check(prompt.contains("sandbox_probe") || prompt.contains("NEXT_EXPERIMENTS"),
                "formatForPrompt usable in PATH/TRIAGE");
    }

    private static void rejectsUnknownEntry() {
        String conclusion = """
                {"nextExperiments":[{
                  "entryRef":"entry:missing",
                  "objective":"probe",
                  "track":"UNAUTH",
                  "pathRunRefs":["pathrun-1"]
                }]}
                """;
        NextExperimentSteps.ParseResult parsed = NextExperimentSteps.parseAndValidate(
                conclusion, Set.of("entry:e1"), Set.of("pathrun-1"));
        check(parsed.steps().isEmpty(), "unknown entry rejected");
        check(parsed.rejected().contains("ENTRYPOINT_NOT_FOUND"), "ENTRYPOINT_NOT_FOUND");
    }

    /** STATIC_ONLY 对比不得提升为 bypassed/confirmed；AUTH_GAP 闸门不变。 */
    private static void rejectsStaticOnlyBypassClaim() {
        String conclusion = """
                {"nextExperiments":[{
                  "entryRef":"entry:e1",
                  "objective":"STATIC_ONLY already 已绕过 on this route",
                  "track":"UNAUTH",
                  "contrastStatus":"STATIC_ONLY",
                  "techniqueId":"ALG_NONE"
                }]}
                """;
        NextExperimentSteps.ParseResult parsed = NextExperimentSteps.parseAndValidate(
                conclusion, Set.of("entry:e1"), Set.of());
        check(parsed.steps().isEmpty(), "STATIC_ONLY bypass claim rejected");
        check(parsed.rejected().contains("STATIC_ONLY_CANNOT_CONFIRM_BYPASS"),
                "STATIC_ONLY_CANNOT_CONFIRM_BYPASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
