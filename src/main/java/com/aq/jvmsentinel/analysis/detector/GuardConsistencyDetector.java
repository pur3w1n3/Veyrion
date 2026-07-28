package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Detects guard dominance / auth annotation inconsistency within a declaring class:
 * some mapped entries declare guards while sibling entries on the same class do not.
 * Does not restate AUTH_GAP as sink-none; emits GUARD_INCONSISTENCY hypotheses.
 */
public final class GuardConsistencyDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROPERTY = "GUARD_INCONSISTENCY";

    @Override
    public String id() {
        return DetectorIds.GUARD_CONSISTENCY;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.GUARD_COVERAGE;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        Map<String, ClassGuardBucket> byClass = new LinkedHashMap<>();
        for (ApiDtos.EntryDto entry : context.entries()) {
            if (entry == null || !"HTTP".equalsIgnoreCase(entry.protocol())) continue;
            String owner = entry.declaringClass() == null ? "" : entry.declaringClass().trim();
            if (owner.isBlank()) continue;
            ClassGuardBucket bucket = byClass.computeIfAbsent(owner, ignored -> new ClassGuardBucket());
            if (hasDeclaredGuard(entry)) {
                bucket.guarded.add(entry);
            } else {
                bucket.unguarded.add(entry);
            }
        }

        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;
        for (Map.Entry<String, ClassGuardBucket> item : byClass.entrySet()) {
            ClassGuardBucket bucket = item.getValue();
            if (bucket.guarded.isEmpty() || bucket.unguarded.isEmpty()) {
                continue;
            }
            for (ApiDtos.EntryDto unguarded : bucket.unguarded) {
                String route = unguarded.route() == null ? "" : unguarded.route();
                String subject = item.getKey() + " " + unguarded.method() + " " + route;
                out.add(new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-gc-dom-" + context.scanId() + "-" + (++ordinal),
                        context.scanId(),
                        PROPERTY,
                        HypothesisFamily.GUARD_COVERAGE,
                        HypothesisLifecycle.CANDIDATE,
                        id() + "/" + version(),
                        unguarded.evidenceRefs(),
                        List.of(),
                        List.of(),
                        subject,
                        "missing-sibling-guard"
                ));
            }
        }
        return List.copyOf(out);
    }

    private static boolean hasDeclaredGuard(ApiDtos.EntryDto entry) {
        for (String precondition : entry.preconditions()) {
            if (precondition == null || precondition.isBlank()) continue;
            String lower = precondition.toLowerCase(Locale.ROOT);
            if (lower.startsWith("role=") || lower.startsWith("tenant=") || lower.startsWith("state=")) {
                return true;
            }
            if (lower.contains("preauthorize") || lower.contains("postauthorize")
                    || lower.contains("secured") || lower.contains("rolesallowed")
                    || lower.contains("preauth") || lower.contains("isadmin")
                    || lower.contains("denyall") || lower.contains("permitall")) {
                return true;
            }
        }
        return false;
    }

    private static final class ClassGuardBucket {
        private final List<ApiDtos.EntryDto> guarded = new ArrayList<>();
        private final List<ApiDtos.EntryDto> unguarded = new ArrayList<>();
    }
}
