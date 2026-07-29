package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler.CompiledPostureExperiment;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * P0-21: project PathRun facts and agent event summaries into PathTrace.
 */
public final class PathTraceProjectionBridge {
    private PathTraceProjectionBridge() {
    }

    public static PathTrace projectFromPathRun(
            ApiDtos.PathRunDto run,
            CompiledPostureExperiment posturePlan,
            List<AgentJsonlTraceConverter.AgentEvent> windowEvents) {
        Objects.requireNonNull(run, "run");
        RuntimePosture posture = posturePlan == null
                ? RuntimePosture.legacyIncomplete()
                : posturePlan.posture();
        String tracePlanId = posturePlan == null ? "" : posturePlan.tracePlanId();
        String worldPackId = posturePlan == null ? "" : posturePlan.worldPackId();
        List<PathTraceProjector.EventSummary> summaries = new ArrayList<>();
        List<PathTrace.ParameterFlowStep> parameterFlow = new ArrayList<>();
        if (Boolean.TRUE.equals(run.entryHit()) || run.httpStatus() >= 200) {
            summaries.add(new PathTraceProjector.EventSummary(
                    TraceEventKind.ENTRY_HIT,
                    run.method() + " " + run.entrypointRef(),
                    run.entrypointRef(),
                    "",
                    false,
                    List.of()));
        }
        if (Boolean.TRUE.equals(run.parameterBound())) {
            summaries.add(new PathTraceProjector.EventSummary(
                    TraceEventKind.PARAMETER_BOUND,
                    "parameter bound",
                    run.entrypointRef(),
                    "PARAMETER_BOUND",
                    false,
                    List.of()));
            parameterFlow.add(new PathTrace.ParameterFlowStep("request", run.entrypointRef(), "", ""));
        }
        // Keep chronological order. Drop CLASS_LOAD flood and duplicate GUARD noise so the
        // TRACE budget retains Controller→Service→Util→Repository→Guard→Effect before failure.
        List<PathTraceProjector.EventSummary> windowSummaries = new ArrayList<>();
        for (AgentJsonlTraceConverter.AgentEvent event :
                windowEvents == null ? List.<AgentJsonlTraceConverter.AgentEvent>of() : windowEvents) {
            if (event == null || isClassLoadNoise(event)) continue;
            windowSummaries.addAll(summariesForAgentEvent(event));
        }
        summaries.addAll(downsampleGuards(windowSummaries));
        for (ApiDtos.SqlEventDto sql : run.sqlEvents() == null ? List.<ApiDtos.SqlEventDto>of() : run.sqlEvents()) {
            if (sql == null) continue;
            boolean effect = sql.maliciousFragmentPresent()
                    || (sql.sqlText() != null && !sql.sqlText().isBlank());
            if (effect) {
                summaries.add(new PathTraceProjector.EventSummary(
                        TraceEventKind.EFFECT_TRIGGERED,
                        truncate(sql.sqlText(), 120),
                        "JDBC",
                        "SQL_EFFECT",
                        false,
                        List.of("EFFECT:JDBC")));
                parameterFlow.add(new PathTrace.ParameterFlowStep("request", "JDBC", sql.sqlText(), "EFFECT:JDBC"));
            } else {
                summaries.add(new PathTraceProjector.EventSummary(
                        TraceEventKind.DEPENDENCY_FAILURE,
                        truncate(sql.sqlText(), 120),
                        "JDBC",
                        "DEPENDENCY_UNAVAILABLE",
                        false,
                        List.of()));
            }
        }
        if (run.httpStatus() == 401 || run.httpStatus() == 403) {
            summaries.add(new PathTraceProjector.EventSummary(
                    TraceEventKind.GUARD_DECISION,
                    "auth challenge",
                    run.entrypointRef(),
                    "AUTH_CHALLENGE",
                    posture.postureKind().name().equals("FORCED_REACHABILITY"),
                    List.of()));
        }
        String correlation = correlationFromRun(run);
        return PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:" + run.pathRunId(),
                run.pathRunId(),
                run.attemptId(),
                run.experimentPlanId() == null ? "" : run.experimentPlanId(),
                tracePlanId,
                run.entrypointRef(),
                run.track(),
                posture,
                worldPackId,
                correlation,
                0,
                summaries,
                parameterFlow,
                256,
                ""));
    }

    private static List<PathTraceProjector.EventSummary> summariesForAgentEvent(
            AgentJsonlTraceConverter.AgentEvent event) {
        Map<String, String> detail = event.detail();
        String pathDebugKind = detail.getOrDefault("pathDebugKind", "");
        String symbol = event.className().isBlank() ? event.method()
                : event.className() + "#" + event.method();
        if ("METHOD_HOP".equals(pathDebugKind)) {
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.METHOD_HOP,
                    detail.getOrDefault("captureMode", "METHOD_HOP") + " at " + symbol,
                    symbol,
                    "",
                    false,
                    List.of()));
        }
        if ("GUARD_DECISION".equals(pathDebugKind)) {
            boolean forced = "true".equalsIgnoreCase(detail.get("forced"));
            String decision = detail.getOrDefault("guardDecision", "OBSERVED");
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.GUARD_DECISION,
                    decision + " at " + symbol,
                    symbol,
                    forced ? "FORCED_ALLOW" : decision,
                    forced,
                    List.of()));
        }
        if ("EFFECT_TRIGGERED".equals(pathDebugKind)) {
            String effectKind = detail.getOrDefault("effectKind", event.eventType());
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.EFFECT_TRIGGERED,
                    effectKind + " at " + symbol,
                    symbol,
                    "EFFECT:" + effectKind,
                    false,
                    List.of("EFFECT:" + effectKind)));
        }
        if ("DEPENDENCY_FAILURE".equals(pathDebugKind)) {
            String failureClass = detail.getOrDefault("failureClass", "DEPENDENCY_UNAVAILABLE");
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.DEPENDENCY_FAILURE,
                    detail.getOrDefault("summary", detail.getOrDefault("sql", "jdbc failure")),
                    symbol,
                    failureClass,
                    false,
                    List.of()));
        }
        if ("DEPENDENCY_CALL".equals(pathDebugKind)) {
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.METHOD_HOP,
                    "dependency call " + detail.getOrDefault("summary", "jdbc"),
                    symbol,
                    "DEPENDENCY_CALL",
                    false,
                    List.of()));
        }
        if ("TRACE_BUDGET_EXHAUSTED".equals(pathDebugKind)) {
            return List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.TRACE_TRUNCATED,
                    "agent maxEvents/maxBytes exhausted — later FORCED hops may be missing",
                    symbol,
                    "TRACE_BUDGET_EXHAUSTED",
                    false,
                    List.of()));
        }
        return switch (event.eventType()) {
            case "HTTP" -> {
                if ("true".equals(detail.get("entryHit"))) {
                    yield List.of(
                            new PathTraceProjector.EventSummary(
                                    TraceEventKind.ENTRY_HIT,
                                    detail.getOrDefault("httpMethod", "GET") + " "
                                            + detail.getOrDefault("route", "/"),
                                    "entry:" + detail.getOrDefault("route", "/"),
                                    "",
                                    false,
                                    List.of()),
                            new PathTraceProjector.EventSummary(
                                    TraceEventKind.PARAMETER_BOUND,
                                    "parameter bound",
                                    symbol,
                                    "PARAMETER_BOUND",
                                    false,
                                    List.of()),
                            new PathTraceProjector.EventSummary(
                                    TraceEventKind.METHOD_HOP,
                                    "handler " + symbol,
                                    symbol,
                                    "",
                                    false,
                                    List.of()));
                }
                yield List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.ENTRY_HIT,
                        detail.getOrDefault("httpMethod", "GET") + " "
                                + detail.getOrDefault("route", "/"),
                        "entry:" + detail.getOrDefault("route", "/"),
                        "",
                        false,
                        List.of()));
            }
            case "JDBC" -> List.of(new PathTraceProjector.EventSummary(
                    TraceEventKind.DEPENDENCY_FAILURE,
                    detail.getOrDefault("sql", detail.getOrDefault("summary", "jdbc")),
                    symbol,
                    detail.getOrDefault("failureClass", "DEPENDENCY_UNAVAILABLE"),
                    false,
                    List.of()));
            case "PROCESS", "FILE", "HTTP_CLIENT", "JNDI" -> {
                String effect = detail.getOrDefault("effectKind", event.eventType());
                yield List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.EFFECT_TRIGGERED,
                        effect + " at " + symbol,
                        symbol,
                        "EFFECT:" + effect,
                        false,
                        List.of("EFFECT:" + effect)));
            }
            case "CLASS_LOAD", "INSTRUMENTATION_CAPABILITY", "INSTRUMENTATION_ERROR" -> List.of(
                    new PathTraceProjector.EventSummary(
                            TraceEventKind.METHOD_HOP,
                            event.eventType() + " at " + symbol,
                            symbol,
                            "",
                            "INSTRUMENTATION_CAPABILITY".equals(event.eventType()),
                            List.of()));
            default -> List.of();
        };
    }

    private static String correlationFromRun(ApiDtos.PathRunDto run) {
        String summary = run.requestSummary() == null ? "" : run.requestSummary();
        int marker = summary.indexOf("correlationId=");
        if (marker < 0) return run.attemptId() == null ? "" : run.attemptId();
        String rest = summary.substring(marker + "correlationId=".length()).trim();
        int end = rest.indexOf(' ');
        return end < 0 ? rest : rest.substring(0, end);
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    static boolean isClassLoadNoise(AgentJsonlTraceConverter.AgentEvent event) {
        if (event == null) return true;
        if ("CLASS_LOAD".equals(event.eventType())
                || "INSTRUMENTATION_CAPABILITY".equals(event.eventType())
                || "INSTRUMENTATION_ERROR".equals(event.eventType())) {
            Map<String, String> detail = event.detail();
            String kind = detail == null ? "" : detail.getOrDefault("pathDebugKind", "");
            // Keep only if sensor explicitly tagged a path-debug kind other than METHOD_HOP noise.
            return kind.isBlank() || "METHOD_HOP".equals(kind);
        }
        return false;
    }

    /** Keep forced guards + first unique subjects; drop repetitive Shiro ENTER noise. */
    static List<PathTraceProjector.EventSummary> downsampleGuards(
            List<PathTraceProjector.EventSummary> summaries) {
        if (summaries == null || summaries.isEmpty()) return List.of();
        List<PathTraceProjector.EventSummary> out = new ArrayList<>();
        java.util.LinkedHashSet<String> seenGuards = new java.util.LinkedHashSet<>();
        int plainGuards = 0;
        final int maxPlainGuards = 12;
        for (PathTraceProjector.EventSummary summary : summaries) {
            if (summary == null) continue;
            if (summary.kind() != TraceEventKind.GUARD_DECISION) {
                out.add(summary);
                continue;
            }
            if (summary.forced() || "FORCED_ALLOW".equalsIgnoreCase(summary.detailCode())) {
                String key = summary.subjectRef() + "|" + summary.detailCode();
                if (seenGuards.add(key)) {
                    out.add(summary);
                }
                continue;
            }
            String key = summary.subjectRef();
            if (!seenGuards.add(key)) continue;
            if (plainGuards >= maxPlainGuards) continue;
            plainGuards++;
            out.add(summary);
        }
        return List.copyOf(out);
    }
}
