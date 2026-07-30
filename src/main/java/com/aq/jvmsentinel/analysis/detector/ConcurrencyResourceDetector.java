package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 说明：P2 CONCURRENCY detector 启发式：TOCTOU/race/lock-window。
 * 不提升 verification status；resource open/close typestate 仍
 * {@link ResourceLifecycleDetector}.
 * 声明 AUDITED 用于启发式 recall（positive/negative/holdout）；非真实 race prover。
 */
public final class ConcurrencyResourceDetector implements Detector {
    public static final String VERSION = "0.2.0-audited-heuristic";
    public static final String PROP_TOCTOU = "TOCTOU_CHECK_THEN_ACT";
    public static final String PROP_RACE_WINDOW = "RACE_WINDOW_HEURISTIC";
    public static final String PROP_LOCK_GAP = "LOCK_TRANSACTION_GAP";

    private static final Set<String> CHECK_NAMES = Set.of(
            "exists", "contains", "containskey", "get", "isEmpty", "size", "findbyid", "findOne");
    private static final Set<String> ACT_NAMES = Set.of(
            "delete", "remove", "put", "set", "save", "write", "rename", "mkdir", "create",
            "update", "insert");
    private static final Set<String> LOCK_NAMES = Set.of(
            "lock", "trylock", "unlock", "synchronize", "synchronized",
            "begin", "commit", "rollback", "withlock", "executeintransaction");

    @Override
    public String id() {
        return DetectorIds.CONCURRENCY_RESOURCE;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.CONCURRENCY;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;

        Map<String, CallerSignals> byCaller = new HashMap<>();
        for (BytecodeFactIndex.CallEdge edge : context.staticFacts().callEdges()) {
            if (edge == null) continue;
            String caller = edge.callerOwner() + "#" + edge.callerName();
            CallerSignals signals = byCaller.computeIfAbsent(caller, ignored -> new CallerSignals());
            String targetOwner = normalize(edge.targetOwner());
            String targetName = edge.targetName() == null ? "" : edge.targetName();
            String lowerName = targetName.toLowerCase(Locale.ROOT);

            if (CHECK_NAMES.contains(lowerName)
                    || targetOwner.endsWith("/File") && "exists".equals(lowerName)) {
                signals.checks.add(targetOwner + "#" + targetName);
            }
            if (ACT_NAMES.contains(lowerName)
                    || (targetOwner.endsWith("/File")
                    && ("delete".equals(lowerName) || "renameto".equals(lowerName)))) {
                signals.acts.add(targetOwner + "#" + targetName);
            }
            if (LOCK_NAMES.contains(lowerName)
                    || targetOwner.contains("Lock")
                    || targetOwner.contains("Transaction")) {
                signals.locks.add(targetOwner + "#" + targetName);
            }
            if (targetOwner.contains("Thread") && "start".equals(lowerName)
                    || targetOwner.contains("Executor") && lowerName.startsWith("submit")
                    || targetOwner.contains("Executor") && "execute".equals(lowerName)) {
                signals.async = true;
            }
        }

        for (Map.Entry<String, CallerSignals> item : byCaller.entrySet()) {
            CallerSignals signals = item.getValue();
            String caller = item.getKey().replace('/', '.');
            if (!signals.checks.isEmpty() && !signals.acts.isEmpty() && signals.locks.isEmpty()) {
                out.add(hypothesis(context, ++ordinal, PROP_TOCTOU, caller,
                        "check-then-act-without-lock"));
            }
            if (signals.async && !signals.acts.isEmpty() && signals.locks.isEmpty()) {
                out.add(hypothesis(context, ++ordinal, PROP_RACE_WINDOW, caller,
                        "async-mutate-without-lock"));
            }
            if (!signals.acts.isEmpty() && signals.locks.isEmpty()
                    && caller.toLowerCase(Locale.ROOT).contains("shared")) {
                out.add(hypothesis(context, ++ordinal, PROP_LOCK_GAP, caller,
                        "shared-mutate-without-transaction"));
            }
        }
        return List.copyOf(out);
    }

    private static SecurityHypothesis hypothesis(DetectorContext context, int ordinal,
                                                 String property, String source, String effect) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-conc-" + context.scanId() + "-" + ordinal,
                context.scanId(),
                property,
                HypothesisFamily.CONCURRENCY,
                HypothesisLifecycle.CANDIDATE,
                DetectorIds.CONCURRENCY_RESOURCE + "/" + VERSION,
                List.of(),
                List.of(),
                List.of(),
                truncate(source),
                effect);
    }

    private static String normalize(String owner) {
        return owner == null ? "" : owner.replace('.', '/');
    }

    private static String truncate(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }

    private static final class CallerSignals {
        private final Set<String> checks = new HashSet<>();
        private final Set<String> acts = new HashSet<>();
        private final Set<String> locks = new HashSet<>();
        private boolean async;
    }
}
