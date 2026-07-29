package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * P0-21: server-owned runtime posture decisions. AI/frontend cannot supply forced reachability policy.
 */
public final class RuntimePostureOrchestrator {
    private static final Set<String> FORBIDDEN_CLIENT_OVERRIDE_KEYS = Set.of(
            "command", "image", "mount", "mounts", "network", "uid", "budget",
            "forcedreachability", "forcedguardrefs", "posturekind", "postureprovenance",
            "dockeronly", "identitytrackwire");

    private RuntimePostureOrchestrator() {
    }

    public static RuntimePosture unauth() {
        return RuntimePosture.unauth();
    }

    public static RuntimePosture coveragePosture() {
        return RuntimePosture.coverage();
    }

    public static List<RuntimePosture> planDefaultPostures(
            List<String> guardRefs,
            boolean bypassCandidate) {
        List<RuntimePosture> postures = new ArrayList<>();
        postures.add(unauth());
        postures.add(coveragePosture());
        List<String> eligible = filterEligibleGuards(guardRefs);
        if (!eligible.isEmpty()) {
            postures.add(RuntimePosture.forced(eligible));
        } else {
            postures.add(RuntimePosture.forced(List.of()));
        }
        if (bypassCandidate) {
            postures.add(RuntimePosture.bypass());
        }
        return List.copyOf(postures);
    }

    public static RuntimePosture authorizeForcedReachability(
            boolean dockerSandbox,
            boolean hostExecution,
            Map<String, ?> clientOverrides) {
        rejectClientOverrides(clientOverrides);
        if (hostExecution) {
            throw new SecurityException("HOST_EXECUTION_DENIED");
        }
        if (!dockerSandbox) {
            throw new SecurityException("FORCED_REACHABILITY_DOCKER_ONLY");
        }
        List<String> guardRefs = extractGuardRefs(clientOverrides);
        for (String ref : guardRefs) {
            if (ForcedGuardKind.isForbiddenForceTarget(ref)) {
                throw new SecurityException("FORBIDDEN_FORCE_TARGET:" + ref);
            }
        }
        return RuntimePosture.forced(guardRefs);
    }

    private static void rejectClientOverrides(Map<String, ?> clientOverrides) {
        if (clientOverrides == null || clientOverrides.isEmpty()) {
            return;
        }
        for (String key : clientOverrides.keySet()) {
            if (key == null) {
                continue;
            }
            String normalized = key.trim().toLowerCase(Locale.ROOT);
            if (FORBIDDEN_CLIENT_OVERRIDE_KEYS.contains(normalized)) {
                throw new SecurityException("CLIENT_POLICY_OVERRIDE_DENIED:" + key);
            }
        }
    }

    private static List<String> extractGuardRefs(Map<String, ?> clientOverrides) {
        if (clientOverrides == null) {
            return List.of();
        }
        Object raw = clientOverrides.get("serverGuardRefs");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> refs = new ArrayList<>();
        for (Object item : list) {
            if (item != null && !item.toString().isBlank()) {
                refs.add(item.toString().trim());
            }
        }
        return List.copyOf(refs);
    }

    private static List<String> filterEligibleGuards(List<String> guardRefs) {
        if (guardRefs == null || guardRefs.isEmpty()) {
            return List.of();
        }
        List<String> eligible = new ArrayList<>();
        for (String ref : guardRefs) {
            if (ref == null || ref.isBlank()) {
                continue;
            }
            if (ForcedGuardKind.isForbiddenForceTarget(ref)) {
                continue;
            }
            if (ForcedGuardKind.tryParse(ref).isPresent()
                    || ref.toUpperCase(Locale.ROOT).startsWith("GUARD:")) {
                eligible.add(ref.trim());
            }
        }
        return List.copyOf(eligible);
    }

    public static RuntimePostureKind defaultKindForWire(String identityTrackWire) {
        Objects.requireNonNull(identityTrackWire, "identityTrackWire");
        return switch (identityTrackWire.trim().toUpperCase(Locale.ROOT)) {
            case "UNAUTH" -> RuntimePostureKind.UNAUTH;
            case "ADMIN", "USER" -> RuntimePostureKind.COVERAGE_POSTURE;
            case "BYPASS_CANDIDATE" -> RuntimePostureKind.BYPASS;
            default -> RuntimePostureKind.UNAUTH;
        };
    }
}
