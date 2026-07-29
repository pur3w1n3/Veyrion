package com.aq.jvmsentinel;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * CI gate runner for curated main-style acceptance tests.
 * Fails closed when zero tests execute or zero assertions are recorded.
 */
public final class AcceptanceTestRunner {
    /**
     * Curated P0 gate: coordinator-first for fast signal, then persistence and lifecycle.
     */
    static final List<String> GATE_CLASSES = List.of(
            "com.aq.jvmsentinel.SchemaContractAcceptanceTest",
            "com.aq.jvmsentinel.ArchitectureBaselineAcceptanceTest",
            "com.aq.jvmsentinel.CiGateAcceptanceTest",
            "com.aq.jvmsentinel.AuditPipelineCoordinatorAcceptanceTest",
            "com.aq.jvmsentinel.ControlPlanePersistenceAcceptanceTest",
            "com.aq.jvmsentinel.StaticFactPersistenceAcceptanceTest",
            "com.aq.jvmsentinel.CrossMethodFindingBindAcceptanceTest",
            "com.aq.jvmsentinel.SecurityHypothesisAcceptanceTest",
            "com.aq.jvmsentinel.NonTaintDetectorAcceptanceTest",
            "com.aq.jvmsentinel.P2DetectorEntryAcceptanceTest",
            "com.aq.jvmsentinel.CoverageMatrixAcceptanceTest",
            "com.aq.jvmsentinel.ArtifactUniverseAcceptanceTest",
            "com.aq.jvmsentinel.EvidenceGraphAcceptanceTest",
            "com.aq.jvmsentinel.ControlPlaneDecoupleAcceptanceTest",
            "com.aq.jvmsentinel.ProviderSpiAcceptanceTest",
            "com.aq.jvmsentinel.HypothesisExperimentAcceptanceTest",
            "com.aq.jvmsentinel.TestAnalyzerAcceptanceTest",
            "com.aq.jvmsentinel.SecondLanguageAnalyzerAcceptanceTest",
            "com.aq.jvmsentinel.ProductionFeaturesAcceptanceTest",
            "com.aq.jvmsentinel.PipelineTerminalLifecycleAcceptanceTest",
            "com.aq.jvmsentinel.PipelineRestartRecoveryAcceptanceTest",
            "com.aq.jvmsentinel.ai.ProbeAttemptIdentityAcceptanceTest",
            "com.aq.jvmsentinel.ai.TriageConclusionFidelityAcceptanceTest",
            "com.aq.jvmsentinel.ai.TriageFindingAttachAcceptanceTest",
            "com.aq.jvmsentinel.ai.AuthMultiRoundGateAcceptanceTest",
            "com.aq.jvmsentinel.ai.AuthBypassFeasibilityAcceptanceTest",
            "com.aq.jvmsentinel.ai.CodeQueryKindAcceptanceTest",
            "com.aq.jvmsentinel.analysis.kernel.StaticAnalysisKernelAcceptanceTest",
            "com.aq.jvmsentinel.ai.PathTriageProbeGateAcceptanceTest",
            "com.aq.jvmsentinel.ai.PathExplorationContractAcceptanceTest",
            "com.aq.jvmsentinel.ai.SandboxProbeSecurityDenialAcceptanceTest",
            "com.aq.jvmsentinel.ai.tool.AiToolRegistryAcceptanceTest",
            "com.aq.jvmsentinel.ai.PathTriageEffectiveProbeAcceptanceTest",
            "com.aq.jvmsentinel.worker.RequestWindowSqlProjectionAcceptanceTest",
            "com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutorAcceptanceTest",
            "com.aq.jvmsentinel.worker.ExperimentPlanReplayIdentityAcceptanceTest",
            "com.aq.jvmsentinel.worker.DynamicConfirmedGateAcceptanceTest",
            "com.aq.jvmsentinel.worker.DynamicSuspectedNoiseGateAcceptanceTest",
            "com.aq.jvmsentinel.worker.EntryHitParameterBoundAcceptanceTest",
            "com.aq.jvmsentinel.analysis.FindingRankerAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.EntryParameterExperimentCompilerAcceptanceTest",
            "com.aq.jvmsentinel.domain.pathdebug.PathDebugContractAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.TracePlanCompilerAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompilerAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.WorldPackPlannerAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestratorAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.PathTraceProjectorAcceptanceTest",
            "com.aq.jvmsentinel.PathDebugPersistenceAcceptanceTest",
            "com.aq.jvmsentinel.control.service.ProbePlanPostureIntegrationAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.PathRunMapLegacyAcceptanceTest",
            "com.aq.jvmsentinel.ai.PathTraceQueryDenialAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.PathTraceObservationBridgeAcceptanceTest",
            "com.aq.jvmsentinel.analysis.experiment.PathDebugMinimumAcceptanceTest",
            "com.aq.jvmsentinel.analysis.recall.PracticalRecallBaselineAcceptanceTest",
            "com.aq.jvmsentinel.analysis.BootPortCandidateHarvesterAcceptanceTest",
            "com.aq.jvmsentinel.SingleEntryDebugBaselineAcceptanceTest",
            "com.aq.jvmsentinel.AuthIdentityTrackAcceptanceTest",
            "com.aq.jvmsentinel.GuiSemanticsContractAcceptanceTest",
            "com.aq.jvmsentinel.GuiLayoutContractAcceptanceTest",
            "com.aq.jvmsentinel.provider.ProviderOutboundBoundaryAcceptanceTest",
            "com.aq.jvmsentinel.provider.LiveProviderRoundAcceptanceTest",
            "com.aq.jvmsentinel.LiveTrustedDockerMultiRequestAcceptanceTest",
            "com.aq.jvmsentinel.LiveJdbcH3AcceptanceTest",
            "com.aq.jvmsentinel.domain.runtime.HardenedRuntimeAttestationAcceptanceTest",
            "com.aq.jvmsentinel.sandbox.SandboxHardeningAcceptanceTest",
            "com.aq.jvmsentinel.verification.VerifiedGateAcceptanceTest",
            "com.aq.jvmsentinel.desktop.DesktopPackagingAcceptanceTest",
            "com.aq.jvmsentinel.analysis.framework.WarServletFrameworkAdapterAcceptanceTest"
    );

    public record Result(int executed, int assertions, List<String> failures) {
        public boolean passed() {
            return failures.isEmpty() && executed > 0 && assertions > 0;
        }
    }

    public static void main(String[] args) throws Exception {
        Result result = runGate();
        System.out.println("Acceptance gate summary: executed=" + result.executed()
                + " assertions=" + result.assertions());
        if (!result.passed()) {
            for (String failure : result.failures()) {
                System.err.println(failure);
            }
            if (result.executed() == 0 || result.assertions() == 0) {
                System.err.println("FAIL: acceptance gate requires non-zero executed tests and assertions");
            }
            System.exit(1);
        }
        System.out.println("AcceptanceTestRunner: PASS");
    }

    public static Result runGate() throws Exception {
        int executed = 0;
        int assertions = 0;
        List<String> failures = new ArrayList<>();

        for (String className : GATE_CLASSES) {
            AcceptanceAssertions.reset();
            long started = System.nanoTime();
            try {
                Class<?> testClass = Class.forName(className);
                Method main = testClass.getMethod("main", String[].class);
                main.invoke(null, (Object) new String[0]);
                int testAssertions = assertionCount(testClass);
                if (testAssertions <= 0) {
                    failures.add(className + ": completed without recorded assertions");
                    continue;
                }
                executed++;
                assertions += testAssertions;
                long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
                System.out.println(className + ": PASS (" + testAssertions + " assertions, " + elapsedMs + "ms)");
            } catch (Throwable failure) {
                Throwable root = rootCause(failure);
                failures.add(className + ": " + root.getClass().getSimpleName() + " - " + root.getMessage());
                root.printStackTrace(System.err);
            }
        }

        return new Result(executed, assertions, failures);
    }

    private static int assertionCount(Class<?> testClass) {
        int shared = AcceptanceAssertions.get();
        if (shared > 0) {
            return shared;
        }
        try {
            Field field = testClass.getDeclaredField("ASSERTIONS");
            field.setAccessible(true);
            Object value = field.get(null);
            if (value instanceof AtomicInteger counter) {
                return counter.get();
            }
        } catch (ReflectiveOperationException ignored) {
            // fall through
        }
        return 0;
    }

    private static Throwable rootCause(Throwable failure) {
        Throwable current = failure;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }
}
