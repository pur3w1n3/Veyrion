package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * P2 STATE detector: cross-request state machine / repeat-submit / quota heuristics.
 * Emits {@link HypothesisFamily#STATE} candidates only — never elevates verification status.
 * Declared AUDITED for heuristic recall (positive/negative/holdout); not a full state-machine solver.
 */
public final class StateSequenceDetector implements Detector {
    public static final String VERSION = "0.2.0-audited-heuristic";
    public static final String PROP_STATE_TRANSITION_GAP = "STATE_TRANSITION_GAP";
    public static final String PROP_REPEAT_SUBMIT = "REPEAT_SUBMIT_RISK";
    public static final String PROP_QUOTA_INVARIANT = "QUOTA_FLOW_INVARIANT";

    private static final Pattern STATE_PRECONDITION = Pattern.compile("(?i)^state=");
    private static final Pattern MUTATING_FLOW = Pattern.compile(
            "(?i)/(submit|confirm|approve|commit|finalize|checkout|pay|transfer|redeem)(/|$)");
    private static final Pattern IDEMPOTENCY_HINT = Pattern.compile(
            "(?i)(idempoten|dedup|once|nonce|request[-_]?id|client[-_]?token)");
    private static final Pattern QUOTA_FLOW = Pattern.compile(
            "(?i)/(quota|credit|balance|budget|limit|coupon|voucher|inventory)(/|$)");

    @Override
    public String id() {
        return DetectorIds.STATE_SEQUENCE;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.STATE;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int ordinal = 0;

        boolean anyStateDeclared = false;
        for (ApiDtos.EntryDto entry : context.entries()) {
            if (entry == null || !"HTTP".equalsIgnoreCase(entry.protocol())) continue;
            if (hasStatePrecondition(entry)) {
                anyStateDeclared = true;
            }
        }

        for (ApiDtos.EntryDto entry : context.entries()) {
            if (entry == null || !"HTTP".equalsIgnoreCase(entry.protocol())) continue;
            String route = entry.route() == null ? "" : entry.route();
            String subject = (entry.declaringClass() == null ? "entry" : entry.declaringClass())
                    + " " + entry.method() + " " + route;

            if (anyStateDeclared && isMutatingFlow(route) && !hasStatePrecondition(entry)) {
                String key = PROP_STATE_TRANSITION_GAP + "|" + subject;
                if (seen.add(key)) {
                    out.add(hypothesis(context, ++ordinal, PROP_STATE_TRANSITION_GAP, subject,
                            "missing-state-precondition", entry.evidenceRefs()));
                }
            }

            if (isMutatingFlow(route) && !hasIdempotencyHint(entry, route)) {
                String key = PROP_REPEAT_SUBMIT + "|" + subject;
                if (seen.add(key)) {
                    out.add(hypothesis(context, ++ordinal, PROP_REPEAT_SUBMIT, subject,
                            "repeat-submit-without-idempotency", entry.evidenceRefs()));
                }
            }

            if (QUOTA_FLOW.matcher(route).find() && !hasStatePrecondition(entry)
                    && !hasQuotaGuard(entry)) {
                String key = PROP_QUOTA_INVARIANT + "|" + subject;
                if (seen.add(key)) {
                    out.add(hypothesis(context, ++ordinal, PROP_QUOTA_INVARIANT, subject,
                            "quota-flow-without-invariant-guard", entry.evidenceRefs()));
                }
            }
        }
        return List.copyOf(out);
    }

    private static SecurityHypothesis hypothesis(DetectorContext context, int ordinal,
                                                 String property, String source, String effect,
                                                 List<String> evidenceRefs) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-state-" + context.scanId() + "-" + ordinal,
                context.scanId(),
                property,
                HypothesisFamily.STATE,
                HypothesisLifecycle.CANDIDATE,
                DetectorIds.STATE_SEQUENCE + "/" + VERSION,
                evidenceRefs,
                List.of(),
                List.of(),
                truncate(source),
                effect);
    }

    private static boolean hasStatePrecondition(ApiDtos.EntryDto entry) {
        for (String precondition : entry.preconditions()) {
            if (precondition == null || precondition.isBlank()) continue;
            if (STATE_PRECONDITION.matcher(precondition.trim()).find()) return true;
        }
        return false;
    }

    private static boolean isMutatingFlow(String route) {
        return MUTATING_FLOW.matcher(route == null ? "" : route).find();
    }

    private static boolean hasIdempotencyHint(ApiDtos.EntryDto entry, String route) {
        if (IDEMPOTENCY_HINT.matcher(route == null ? "" : route).find()) return true;
        for (String parameter : entry.parameters()) {
            if (parameter != null && IDEMPOTENCY_HINT.matcher(parameter).find()) return true;
        }
        for (String precondition : entry.preconditions()) {
            if (precondition != null && IDEMPOTENCY_HINT.matcher(precondition).find()) return true;
        }
        return false;
    }

    private static boolean hasQuotaGuard(ApiDtos.EntryDto entry) {
        for (String precondition : entry.preconditions()) {
            if (precondition == null || precondition.isBlank()) continue;
            String lower = precondition.toLowerCase(Locale.ROOT);
            if (lower.contains("quota") || lower.contains("balance") || lower.contains("credit")
                    || lower.contains("limit") || lower.startsWith("role=")
                    || lower.contains("preauthorize")) {
                return true;
            }
        }
        return false;
    }

    private static String truncate(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }
}
