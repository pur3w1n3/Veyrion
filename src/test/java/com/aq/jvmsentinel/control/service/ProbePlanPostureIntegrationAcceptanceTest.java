package com.aq.jvmsentinel.control.service;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** PostureExperimentCompiler plans are used when building flood probe plans. */
public final class ProbePlanPostureIntegrationAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ControlPlaneStore store = new ControlPlaneStore();
        String now = Instant.now().toString();
        store.createProject("local", "posture", now, "test");
        ApiDtos.EntryDto entry = entry();
        ApiDtos.ScanDto dto = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, "local", "digest-posture", "scan-posture",
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(dto, Map.of(), List.of(), List.of()), "test");
        ControlPlaneStore.ScanRecord scan = store.requireScan("scan-posture");
        ProbePlanService service = new ProbePlanService(store, (projectId, scanId) -> List.of());
        ProbePlanService.ProbePlan plan = service.buildProbePlan(scan, null);
        check(!plan.probes().isEmpty(), "probe plan is non-empty");
        boolean hasPosturePlan = plan.probes().stream()
                .anyMatch(probe -> probe.experimentPlanId() != null
                        && probe.experimentPlanId().startsWith("plan:posture:"));
        check(hasPosturePlan, "probe carries posture experimentPlanId");
        boolean hasUnauth = plan.probes().stream()
                .anyMatch(probe -> "UNAUTH".equals(probe.track()));
        check(hasUnauth, "UNAUTH posture track present");
        ProbePlanService.PostureExpansionResult expansion = service.expandProbesByPostureDetailed(
                scan, List.of(entry), List.of(ProbePlanService.probeTargetFor(entry)), false, 16);
        boolean forcedAbsent = expansion.probes().stream()
                .noneMatch(probe -> probe.experimentPlanId() != null
                        && probe.experimentPlanId().contains("forced_reachability"));
        check(forcedAbsent, "FORCED_REACHABILITY omitted when dockerSandbox=false");
        System.out.println("ProbePlanPostureIntegrationAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static ApiDtos.EntryDto entry() {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "local", "digest-posture", "scan-posture",
                "entry-1", "HTTP", "GET", "/api/demo", "DemoController", "app",
                List.of("name=query"), List.of(), ApiDtos.STATIC_INFERRED, 0.8, 100,
                List.of("evidence-entry-1"));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}
