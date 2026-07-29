package com.aq.jvmsentinel.domain.pathdebug;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Server-owned runtime posture for one experiment (P0-21).
 * AI/frontend cannot supply forcedGuardRefs or enable FORCED_REACHABILITY.
 */
public record RuntimePosture(
        RuntimePostureKind postureKind,
        String postureProvenance,
        List<String> forcedGuardRefs,
        boolean dockerOnly,
        String identityTrackWire
) {
    public static final String PROVENANCE_SERVER_FIXED = "SERVER_FIXED_POLICY";
    public static final String PROVENANCE_SCAN_AUTH = "SCAN_AUTH_POSTURE";
    public static final String PROVENANCE_INSTRUMENTATION = "INSTRUMENTATION_REACHABILITY";
    public static final String PROVENANCE_AUTH_POC = "AUTH_POC_CANDIDATE";
    public static final String PROVENANCE_LEGACY = "LEGACY_DYNAMIC_INCOMPLETE";

    public RuntimePosture {
        Objects.requireNonNull(postureKind, "postureKind");
        postureProvenance = postureProvenance == null || postureProvenance.isBlank()
                ? PROVENANCE_SERVER_FIXED : postureProvenance.trim();
        forcedGuardRefs = List.copyOf(forcedGuardRefs == null ? List.of() : forcedGuardRefs);
        identityTrackWire = identityTrackWire == null || identityTrackWire.isBlank()
                ? defaultTrackWire(postureKind) : identityTrackWire.trim().toUpperCase();
        if (postureKind == RuntimePostureKind.FORCED_REACHABILITY && !dockerOnly) {
            throw new IllegalArgumentException("FORCED_REACHABILITY requires dockerOnly=true");
        }
        for (String ref : forcedGuardRefs) {
            if (ForcedGuardKind.isForbiddenForceTarget(ref)) {
                throw new IllegalArgumentException("FORBIDDEN_FORCE_TARGET:" + ref);
            }
        }
    }

    public static RuntimePosture unauth() {
        return new RuntimePosture(RuntimePostureKind.UNAUTH, PROVENANCE_SERVER_FIXED,
                List.of(), true, "UNAUTH");
    }

    public static RuntimePosture coverage() {
        return new RuntimePosture(RuntimePostureKind.COVERAGE_POSTURE, PROVENANCE_SCAN_AUTH,
                List.of(), true, "ADMIN");
    }

    public static RuntimePosture forced(List<String> guardRefs) {
        return new RuntimePosture(RuntimePostureKind.FORCED_REACHABILITY, PROVENANCE_INSTRUMENTATION,
                guardRefs == null ? List.of() : guardRefs, true, "ADMIN");
    }

    public static RuntimePosture bypass() {
        return new RuntimePosture(RuntimePostureKind.BYPASS, PROVENANCE_AUTH_POC,
                List.of(), true, "BYPASS_CANDIDATE");
    }

    public static RuntimePosture legacyIncomplete() {
        return new RuntimePosture(RuntimePostureKind.UNAUTH, PROVENANCE_LEGACY,
                List.of(), false, "UNAUTH");
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("postureKind", postureKind.name());
        map.put("postureProvenance", postureProvenance);
        map.put("forcedGuardRefs", new ArrayList<>(forcedGuardRefs));
        map.put("dockerOnly", dockerOnly);
        map.put("identityTrackWire", identityTrackWire);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static RuntimePosture fromMap(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return legacyIncomplete();
        }
        RuntimePostureKind kind = RuntimePostureKind.tryParse(string(map.get("postureKind")))
                .orElse(RuntimePostureKind.UNAUTH);
        String provenance = string(map.get("postureProvenance"));
        if (provenance.isBlank()) {
            provenance = PROVENANCE_LEGACY;
        }
        List<String> guards = new ArrayList<>();
        Object rawGuards = map.get("forcedGuardRefs");
        if (rawGuards instanceof List<?> list) {
            for (Object item : list) {
                if (item != null && !item.toString().isBlank()) {
                    guards.add(item.toString());
                }
            }
        }
        boolean dockerOnly = map.get("dockerOnly") instanceof Boolean b ? b
                : kind == RuntimePostureKind.FORCED_REACHABILITY;
        String track = string(map.get("identityTrackWire"));
        if (PROVENANCE_LEGACY.equals(provenance) && kind == RuntimePostureKind.FORCED_REACHABILITY) {
            // Never invent forced posture from incomplete legacy payloads.
            return legacyIncomplete();
        }
        return new RuntimePosture(kind, provenance, guards, dockerOnly, track);
    }

    private static String defaultTrackWire(RuntimePostureKind kind) {
        return switch (kind) {
            case UNAUTH -> "UNAUTH";
            case COVERAGE_POSTURE, FORCED_REACHABILITY -> "ADMIN";
            case BYPASS -> "BYPASS_CANDIDATE";
        };
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString().trim();
    }
}
