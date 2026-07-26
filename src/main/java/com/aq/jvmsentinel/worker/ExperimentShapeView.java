package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Normalizes one PathRun into a single human/AI debug shape:
 * HTTP line, bind flags, SQL texts, stop reason, dependency mode.
 * Never upgrades verification status.
 */
public final class ExperimentShapeView {
    private ExperimentShapeView() { }

    public record Shape(
            String pathRunId,
            String entrypointRef,
            String track,
            String httpLine,
            int httpStatus,
            Boolean entryHit,
            Boolean parameterBound,
            List<String> sqlTexts,
            String stopReason,
            String outcomeClass,
            String dependencyMode,
            String verificationStatus,
            List<String> evidenceRefs
    ) {
        public Shape {
            Objects.requireNonNull(pathRunId, "pathRunId");
            entrypointRef = entrypointRef == null ? "" : entrypointRef;
            track = track == null ? "" : track;
            httpLine = httpLine == null ? "" : httpLine;
            sqlTexts = List.copyOf(sqlTexts == null ? List.of() : sqlTexts);
            stopReason = stopReason == null ? "UNKNOWN" : stopReason;
            outcomeClass = outcomeClass == null ? "UNKNOWN" : outcomeClass;
            dependencyMode = dependencyMode == null || dependencyMode.isBlank() ? "MOCK" : dependencyMode;
            verificationStatus = verificationStatus == null ? "DYNAMIC_SUSPECTED" : verificationStatus;
            if ("VERIFIED".equals(verificationStatus)) {
                throw new IllegalArgumentException("experiment shape must not claim VERIFIED");
            }
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        }
    }

    public static Shape fromPathRun(ApiDtos.PathRunDto run) {
        Objects.requireNonNull(run, "run");
        List<String> sql = new ArrayList<>();
        if (run.sqlEvents() != null) {
            for (ApiDtos.SqlEventDto event : run.sqlEvents()) {
                if (event != null && event.sqlText() != null && !event.sqlText().isBlank()) {
                    sql.add(event.sqlText());
                    if (sql.size() >= 16) break;
                }
            }
        }
        String summary = run.requestSummary() == null || run.requestSummary().isBlank()
                ? run.method() + " " + run.entrypointRef()
                : run.requestSummary();
        return new Shape(
                run.pathRunId(),
                run.entrypointRef(),
                run.track(),
                summary,
                run.httpStatus(),
                run.entryHit(),
                run.parameterBound(),
                sql,
                run.stopReason(),
                run.outcomeClass(),
                run.identityProvenance(),
                run.verificationStatus(),
                run.evidenceRefs());
    }

    public static List<Shape> fromPathRuns(List<ApiDtos.PathRunDto> pathRuns) {
        if (pathRuns == null || pathRuns.isEmpty()) return List.of();
        List<Shape> shapes = new ArrayList<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null) continue;
            shapes.add(fromPathRun(run));
            if (shapes.size() >= 64) break;
        }
        return List.copyOf(shapes);
    }

    public static Map<String, Object> toMap(Shape shape) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("pathRunId", shape.pathRunId());
        row.put("entrypointRef", shape.entrypointRef());
        row.put("track", shape.track());
        row.put("httpLine", shape.httpLine());
        row.put("httpStatus", shape.httpStatus());
        row.put("entryHit", shape.entryHit());
        row.put("parameterBound", shape.parameterBound());
        row.put("sqlTexts", shape.sqlTexts());
        row.put("stopReason", shape.stopReason());
        row.put("outcomeClass", shape.outcomeClass());
        row.put("dependencyMode", shape.dependencyMode());
        row.put("verificationStatus", shape.verificationStatus());
        row.put("evidenceRefs", shape.evidenceRefs());
        return row;
    }
}
