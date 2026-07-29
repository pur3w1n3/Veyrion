package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathRunPathDebugView;

import java.util.List;
import java.util.Map;

import java.util.Map;

/** pathRun wire maps mark legacy incomplete for old runs without path-debug fields. */
public final class PathRunMapLegacyAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ApiDtos.PathRunDto legacy = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-legacy", "scan-1", "entry:GET:/x",
                "UNAUTH", "attempt-1", "", "GET", "application/json", "GET /x",
                "HTTP_OBSERVED", 401, true, null, List.of(), "AUTH_CHALLENGE",
                ApiDtos.UNREACHED, List.of("evidence-1"), ApiDtos.MOCK, "no credentials",
                Map.of());
        Map<String, Object> wire = PathDebugWireHelper.enrichPathRunMap(legacy, null);
        check(Boolean.TRUE.equals(wire.get("legacyIncomplete")), "legacyIncomplete=true");
        check(PathRunPathDebugView.LEGACY_MARKER.equals(wire.get("compatibilityMarker")),
                "compatibility marker set");
        check(!wire.containsKey("postureKind") || wire.get("postureKind").toString().isBlank(),
                "no invented postureKind");
        System.out.println("PathRunMapLegacyAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}
