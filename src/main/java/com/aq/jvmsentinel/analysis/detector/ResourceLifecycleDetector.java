package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Skeleton: resource open without close in the same caller (FILE_READ / stream constructors).
 */
public final class ResourceLifecycleDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROPERTY = "RESOURCE_LIFECYCLE_GAP";

    private static final Set<String> OPEN_OWNERS = Set.of(
            "java/io/FileInputStream",
            "java/io/FileOutputStream",
            "java/io/FileReader",
            "java/io/FileWriter",
            "java/net/Socket",
            "java/net/ServerSocket"
    );

    @Override
    public String id() {
        return DetectorIds.RESOURCE_LIFECYCLE;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.TYPESTATE;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;

        Set<String> callersWithClose = new HashSet<>();
        Set<String> callersWithOpen = new HashSet<>();
        List<BytecodeFactIndex.CallEdge> edges = context.staticFacts().callEdges();
        for (BytecodeFactIndex.CallEdge edge : edges) {
            if (edge == null) continue;
            String caller = edge.callerOwner() + "#" + edge.callerName();
            String owner = edge.targetOwner() == null ? "" : edge.targetOwner().replace('.', '/');
            String name = edge.targetName() == null ? "" : edge.targetName();
            if ("close".equals(name)) {
                callersWithClose.add(caller);
            }
            if (OPEN_OWNERS.contains(owner) && ("<init>".equals(name) || "open".equals(name))) {
                callersWithOpen.add(caller);
            }
        }
        for (String caller : callersWithOpen) {
            if (callersWithClose.contains(caller)) continue;
            out.add(new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION,
                    "hyp-res-" + context.scanId() + "-" + (++ordinal),
                    context.scanId(),
                    PROPERTY,
                    HypothesisFamily.TYPESTATE,
                    HypothesisLifecycle.CANDIDATE,
                    id() + "/" + version(),
                    List.of(),
                    List.of(),
                    List.of(),
                    caller.replace('/', '.'),
                    "open-without-close"
            ));
        }

        // Fallback from sink catalog FILE_READ when IR edges unavailable.
        if (edges.isEmpty()) {
            for (ApiDtos.SinkDto sink : context.sinks()) {
                if (sink == null || sink.category() == null) continue;
                String cat = sink.category().toUpperCase(Locale.ROOT);
                if (!cat.contains("FILE") && !cat.equals("ARCHIVE")) continue;
                String symbol = sink.symbol() == null ? cat : sink.symbol();
                out.add(new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-res-" + context.scanId() + "-" + (++ordinal),
                        context.scanId(),
                        PROPERTY,
                        HypothesisFamily.TYPESTATE,
                        HypothesisLifecycle.CANDIDATE,
                        id() + "/" + version(),
                        sink.evidenceRefs(),
                        List.of(),
                        List.of(),
                        truncate(symbol),
                        "file-resource-surface"
                ));
            }
        }
        return List.copyOf(out);
    }

    private static String truncate(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }
}
