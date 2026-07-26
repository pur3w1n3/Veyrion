package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.NextExperimentStep;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Parses PATH / TRIAGE {@code nextExperiments} blocks into sandbox_probe-consumable steps.
 * Rejects AUTH_GAP-only narratives without PathRun or entry references.
 */
public final class NextExperimentSteps {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_STEPS = 8;

    private NextExperimentSteps() { }

    public record ParseResult(List<NextExperimentStep> steps, List<String> rejected) {
        public ParseResult {
            steps = List.copyOf(steps == null ? List.of() : steps);
            rejected = List.copyOf(rejected == null ? List.of() : rejected);
        }
    }

    public static ParseResult parseAndValidate(String conclusionJson, Set<String> allowedEntryRefs,
                                               Set<String> knownPathRunIds) {
        List<NextExperimentStep> steps = new ArrayList<>();
        List<String> rejected = new ArrayList<>();
        if (conclusionJson == null || conclusionJson.isBlank()) {
            return new ParseResult(steps, List.of("EMPTY_CONCLUSION"));
        }
        try {
            JsonNode root = JSON.readTree(extractJsonObject(conclusionJson));
            JsonNode array = root.path("nextExperiments");
            if (!array.isArray() || array.isEmpty()) {
                // Also accept nextValidationSteps alias.
                array = root.path("nextValidationSteps");
            }
            if (!array.isArray()) {
                return new ParseResult(steps, List.of("NO_NEXT_EXPERIMENTS_BLOCK"));
            }
            for (JsonNode item : array) {
                if (steps.size() >= MAX_STEPS) break;
                try {
                    NextExperimentStep step = parseOne(item, allowedEntryRefs, knownPathRunIds);
                    steps.add(step);
                } catch (IllegalArgumentException failure) {
                    rejected.add(failure.getMessage());
                }
            }
        } catch (Exception failure) {
            rejected.add("NEXT_EXPERIMENTS_PARSE_FAILED");
        }
        return new ParseResult(steps, rejected);
    }

    private static NextExperimentStep parseOne(JsonNode item, Set<String> allowedEntryRefs,
                                               Set<String> knownPathRunIds) {
        String entryRef = text(item, "entryRef");
        if (entryRef.isBlank()) entryRef = text(item, "entrypointRef");
        if (!entryRef.startsWith("entry:")) {
            throw new IllegalArgumentException("ENTRYPOINT_REF_MUST_BE_ENTRY");
        }
        if (allowedEntryRefs != null && !allowedEntryRefs.isEmpty() && !allowedEntryRefs.contains(entryRef)) {
            throw new IllegalArgumentException("ENTRYPOINT_NOT_FOUND");
        }
        String objective = text(item, "objective");
        if (objective.isBlank()) objective = text(item, "rationale");
        String objectiveLower = objective.toLowerCase(Locale.ROOT);
        if (objectiveLower.contains("auth_gap")
                && !item.has("pathRunRefs")
                && text(item, "techniqueId").isBlank()) {
            throw new IllegalArgumentException("AUTH_GAP_NARRATIVE_WITHOUT_PATHRUN");
        }
        // STATIC_ONLY contrast may inform planning but must not claim bypass/confirmed.
        boolean claimsBypass = objectiveLower.contains("已绕过") || objectiveLower.contains("bypass confirmed")
                || objectiveLower.contains("已确认绕过") || objectiveLower.contains("confirmed bypass");
        boolean staticOnlyClaim = objectiveLower.contains("static_only")
                || text(item, "contrastStatus").equalsIgnoreCase("STATIC_ONLY");
        if (claimsBypass && staticOnlyClaim) {
            throw new IllegalArgumentException("STATIC_ONLY_CANNOT_CONFIRM_BYPASS");
        }
        IdentityTrack track = IdentityTrack.UNAUTH;
        String trackName = text(item, "track");
        if (!trackName.isBlank()) {
            try {
                track = IdentityTrack.valueOf(trackName.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                throw new IllegalArgumentException("track is invalid");
            }
        }
        List<String> inputs = new ArrayList<>();
        if (item.path("candidateInputs").isArray()) {
            for (JsonNode value : item.path("candidateInputs")) {
                if (inputs.size() >= 8) break;
                if (value != null && value.isTextual()) inputs.add(value.asText());
            }
        }
        List<String> pathRunRefs = new ArrayList<>();
        if (item.path("pathRunRefs").isArray()) {
            for (JsonNode value : item.path("pathRunRefs")) {
                if (value != null && value.isTextual()) {
                    String ref = value.asText();
                    if (knownPathRunIds != null && !knownPathRunIds.isEmpty()
                            && !knownPathRunIds.contains(ref)
                            && !ref.startsWith("pathrun:")) {
                        throw new IllegalArgumentException("PATH_RUN_REF_UNKNOWN");
                    }
                    pathRunRefs.add(ref);
                }
            }
        }
        return new NextExperimentStep(
                entryRef,
                objective,
                track,
                text(item, "techniqueId"),
                inputs,
                pathRunRefs,
                text(item, "rationale"));
    }

    public static String formatForPrompt(List<NextExperimentStep> steps, boolean english) {
        if (steps == null || steps.isEmpty()) {
            return english
                    ? "NEXT_EXPERIMENTS: none (must propose PathRun-grounded steps, not AUTH_GAP essays).\n"
                    : "NEXT_EXPERIMENTS：无（须基于 PathRun 提出可执行下一步，禁止只综述 AUTH_GAP）。\n";
        }
        StringBuilder block = new StringBuilder(english
                ? "NEXT_EXPERIMENTS (server-gated; consumable by sandbox_probe):\n"
                : "NEXT_EXPERIMENTS（服务端闸门；可由 sandbox_probe 消费）：\n");
        int index = 1;
        for (NextExperimentStep step : steps) {
            block.append(index++).append(") ").append(step.entryRef())
                    .append(" track=").append(step.track().name());
            if (!step.techniqueId().isBlank()) {
                block.append(" techniqueId=").append(step.techniqueId());
            }
            block.append(" objective=").append(truncate(step.objective(), 160)).append('\n');
        }
        return block.toString();
    }

    private static String extractJsonObject(String text) {
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start >= 0 && end > start) return text.substring(start, end + 1);
        return text;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? "" : value.asText("").trim();
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    public static Set<String> entryRefs(List<NextExperimentStep> steps) {
        LinkedHashSet<String> refs = new LinkedHashSet<>();
        if (steps != null) {
            for (NextExperimentStep step : steps) refs.add(step.entryRef());
        }
        return Set.copyOf(refs);
    }
}
