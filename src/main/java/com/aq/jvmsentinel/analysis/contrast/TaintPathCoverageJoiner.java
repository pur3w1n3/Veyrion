package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Deterministically joins static taint-path methods to bounded branch coverage observations.
 * A branch hit proves method reachability only; it never proves sink execution or exploitability.
 */
public final class TaintPathCoverageJoiner {
    public static final String STOP_DYNAMIC_BRANCH_REACHED = "DYNAMIC_BRANCH_REACHED";

    public List<StatusUpgrade> join(
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<ApiDtos.PathRunDto> pathRuns) {
        List<BytecodeFactIndex.TaintPath> paths =
                taintPaths == null ? List.of() : taintPaths;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        List<StatusUpgrade> upgrades = new ArrayList<>();
        for (BytecodeFactIndex.TaintPath path : paths) {
            Set<String> pathMethods = pathMethods(path);
            LinkedHashSet<String> runRefs = new LinkedHashSet<>();
            LinkedHashSet<String> matchedMethods = new LinkedHashSet<>();
            for (ApiDtos.PathRunDto run : runs) {
                for (Map.Entry<String, List<Integer>> branch : run.branchHitMap().entrySet()) {
                    if (branch.getValue().isEmpty()) continue;
                    String observed = normalizeMethodKey(branch.getKey());
                    if (pathMethods.contains(observed)) {
                        runRefs.add(run.pathRunId());
                        matchedMethods.add(observed);
                    }
                }
            }
            if (!matchedMethods.isEmpty()) {
                upgrades.add(new StatusUpgrade(
                        path.id(), ContrastStatus.DYNAMIC_REACHED,
                        List.copyOf(runRefs), List.copyOf(matchedMethods),
                        STOP_DYNAMIC_BRANCH_REACHED));
            }
        }
        return List.copyOf(upgrades);
    }

    private static Set<String> pathMethods(BytecodeFactIndex.TaintPath path) {
        LinkedHashSet<String> methods = new LinkedHashSet<>();
        methods.add(normalizeMethodKey(
                path.sourceOwner() + "#" + path.sourceMethod() + path.sourceDescriptor()));
        methods.add(normalizeMethodKey(
                path.sinkOwner() + "#" + path.sinkMethod() + path.sinkDescriptor()));
        for (BytecodeFactIndex.TaintStep step : path.steps()) {
            String symbol = step.symbol();
            int parameter = symbol.indexOf(":parameter-");
            if (parameter >= 0) symbol = symbol.substring(0, parameter);
            methods.add(normalizeMethodKey(symbol));
        }
        methods.remove("");
        return Set.copyOf(methods);
    }

    private static String normalizeMethodKey(String key) {
        if (key == null || key.isBlank()) return "";
        return key.trim().replace('/', '.');
    }

    public record StatusUpgrade(
            String taintPathId,
            ContrastStatus status,
            List<String> pathRunRefs,
            List<String> matchedMethods,
            String stopReason) {
        public StatusUpgrade {
            if (taintPathId == null || taintPathId.isBlank()) {
                throw new IllegalArgumentException("taintPathId cannot be blank");
            }
            if (status != ContrastStatus.DYNAMIC_REACHED) {
                throw new IllegalArgumentException("coverage join only emits DYNAMIC_REACHED");
            }
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
            matchedMethods = List.copyOf(matchedMethods == null ? List.of() : matchedMethods);
            stopReason = stopReason == null ? STOP_DYNAMIC_BRANCH_REACHED : stopReason;
        }
    }
}
