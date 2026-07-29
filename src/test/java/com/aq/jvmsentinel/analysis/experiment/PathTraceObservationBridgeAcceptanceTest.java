package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ObservationKind;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;

import java.util.List;

/** PathTrace projects into RuntimeObservation with instrumentation provenance for forced effects. */
public final class PathTraceObservationBridgeAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        PathTraceProjector.ProjectionInput base = new PathTraceProjector.ProjectionInput(
                "pathtrace-bridge", "pathrun-bridge", "attempt-1", "plan:posture:entry:forced_reachability",
                "trace:entry", "entry:1", "ADMIN", RuntimePosture.forced(List.of("GUARD:AUTH")),
                "worldpack:mock:scan", "corr-1", 0, List.of(), List.of(), 32, "");
        var trace = PathTraceProjector.projectCodeQueryDbUnavailable(base);
        RuntimeObservation obs = PathTraceObservationBridge.fromPathTrace(
                trace, "hyp-1", ExperimentPlanKind.REACHABILITY, List.of("evidence-1"));
        check(obs.successfulProjection(), "projection succeeds");
        check(obs.kind() == ObservationKind.EFFECT || obs.kind() == ObservationKind.DEPENDENCY,
                "dominant kind reflects effect/dependency");
        check(obs.signalCode().startsWith("INSTRUMENTATION_REACHABILITY")
                        || trace.posture().postureKind().name().equals("FORCED_REACHABILITY"),
                "forced reachability encoded in signalCode");
        check(!obs.incrementalSubjects().contains(ObservationKind.EFFECT)
                        || !obs.signalCode().startsWith("INSTRUMENTATION_REACHABILITY"),
                "forced-only effect does not become standalone confirmation subject");
        System.out.println("PathTraceObservationBridgeAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}
