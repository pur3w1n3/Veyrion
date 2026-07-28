package com.aq.jvmsentinel.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses and serializes VULNERABILITY_TRIAGE conclusion JSON with structured rootCause,
 * top-level evidenceRefs, and counterevidence. Fail-closed to INSUFFICIENT_EVIDENCE when
 * required fields are missing — never routes through AUTH bypass PoC serialization.
 */
public final class TriageConclusion {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern FENCED_JSON = Pattern.compile(
            "(?is)```(?:json)?\\s*(\\{.*?\"rootCause\".*?})\\s*```");
    public static final String INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE";
    public static final String CLASSIFICATION_INFERENCE = "INFERENCE";
    private static final int MAX_EVIDENCE_REFS = 64;
    private static final int MAX_COUNTEREVIDENCE = 32;
    private static final int MAX_ATTACK_STEPS = 16;

    private TriageConclusion() { }

    public record ParseResult(
            RootCauseAnalysis rootCause,
            List<String> evidenceRefs,
            List<String> counterevidence,
            List<String> rejected,
            boolean insufficientEvidence
    ) {
        public ParseResult {
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            counterevidence = List.copyOf(counterevidence == null ? List.of() : counterevidence);
            rejected = List.copyOf(rejected == null ? List.of() : rejected);
        }
    }

    public static ParseResult parseAndValidate(String summaryOrJson) {
        List<String> rejected = new ArrayList<>();
        if (summaryOrJson == null || summaryOrJson.isBlank()) {
            return insufficient(null, List.of(), List.of(), List.of("EMPTY_SUMMARY"));
        }
        JsonNode root;
        try {
            root = JSON.readTree(extractJsonObject(summaryOrJson));
        } catch (Exception failure) {
            return insufficient(null, List.of(), List.of(), List.of("TRIAGE_PARSE_FAILED"));
        }
        if (root == null || !root.isObject()) {
            return insufficient(null, List.of(), List.of(), List.of("TRIAGE_NOT_OBJECT"));
        }

        List<String> topRefs = readStringArray(root.path("evidenceRefs"), MAX_EVIDENCE_REFS, rejected,
                "EVIDENCE_REF");
        List<String> counterevidence = readStringArray(root.path("counterevidence"), MAX_COUNTEREVIDENCE,
                rejected, "COUNTEREVIDENCE");

        JsonNode rootCauseNode = root.path("rootCause");
        if (rootCauseNode.isMissingNode() || rootCauseNode.isNull() || !rootCauseNode.isObject()) {
            rejected.add("ROOT_CAUSE_MISSING");
            return insufficient(null, topRefs, counterevidence, rejected);
        }

        List<RootCauseAnalysis.AttackStep> steps = new ArrayList<>();
        JsonNode attackPath = rootCauseNode.path("attackPath");
        if (!attackPath.isArray() || attackPath.isEmpty()) {
            rejected.add("ATTACK_PATH_MISSING");
        } else {
            for (JsonNode stepNode : attackPath) {
                if (steps.size() >= MAX_ATTACK_STEPS) break;
                if (stepNode == null || !stepNode.isObject()) {
                    rejected.add("ATTACK_STEP_INVALID");
                    continue;
                }
                String layer = text(stepNode, "layer");
                String label = text(stepNode, "label");
                if (label.isBlank()) {
                    rejected.add("ATTACK_STEP_LABEL_BLANK");
                    continue;
                }
                List<String> stepRefs = readStringArray(stepNode.path("evidenceRefs"), 16, rejected,
                        "ATTACK_STEP_EVIDENCE");
                if (stepRefs.isEmpty()) {
                    rejected.add("ATTACK_STEP_EVIDENCE_EMPTY");
                    continue;
                }
                try {
                    steps.add(new RootCauseAnalysis.AttackStep(
                            layer.isBlank() ? "unknown" : layer, label, stepRefs));
                } catch (RuntimeException invalid) {
                    rejected.add("ATTACK_STEP_REJECTED");
                }
            }
        }

        String statement = text(rootCauseNode, "rootCauseStatement");
        String affected = text(rootCauseNode, "affectedComponent");
        String cweId = text(rootCauseNode, "cweId");
        String fix = text(rootCauseNode, "fixSuggestion");

        LinkedHashSet<String> aggregated = new LinkedHashSet<>(topRefs);
        for (RootCauseAnalysis.AttackStep step : steps) {
            aggregated.addAll(step.evidenceRefs());
            if (aggregated.size() >= MAX_EVIDENCE_REFS) break;
        }
        List<String> evidenceRefs = List.copyOf(aggregated).stream().limit(MAX_EVIDENCE_REFS).toList();

        boolean missingRequired = steps.isEmpty()
                || statement.isBlank()
                || evidenceRefs.isEmpty();
        if (missingRequired) {
            if (statement.isBlank()) rejected.add("ROOT_CAUSE_STATEMENT_BLANK");
            if (evidenceRefs.isEmpty()) rejected.add("EVIDENCE_REFS_EMPTY");
            RootCauseAnalysis partial = steps.isEmpty() && statement.isBlank() && affected.isBlank()
                    && cweId.isBlank() && fix.isBlank()
                    ? null
                    : new RootCauseAnalysis(steps, statement, affected, cweId, fix);
            return insufficient(partial, evidenceRefs, counterevidence, rejected);
        }

        RootCauseAnalysis analysis = new RootCauseAnalysis(steps, statement, affected, cweId, fix);
        return new ParseResult(analysis, evidenceRefs, counterevidence, rejected, false);
    }

    public static ObjectNode toConclusionNode(String summary, ParseResult parsed) {
        ObjectNode node = JSON.createObjectNode();
        node.put("schemaVersion", 1);
        boolean insufficient = parsed == null || parsed.insufficientEvidence()
                || parsed.rootCause() == null
                || parsed.evidenceRefs().isEmpty();
        node.put("classification", insufficient ? INSUFFICIENT_EVIDENCE : CLASSIFICATION_INFERENCE);
        node.put("summary", summary == null ? "" : summary);
        ArrayNode refs = node.putArray("evidenceRefs");
        if (parsed != null) {
            parsed.evidenceRefs().forEach(refs::add);
        }
        ArrayNode counter = node.putArray("counterevidence");
        if (parsed != null) {
            parsed.counterevidence().forEach(counter::add);
        }
        ObjectNode rootCauseNode = node.putObject("rootCause");
        writeRootCause(rootCauseNode, parsed == null ? null : parsed.rootCause());
        if (parsed != null && !parsed.rejected().isEmpty()) {
            ArrayNode rejected = node.putArray("rejectedTriageFields");
            parsed.rejected().stream().limit(32).forEach(rejected::add);
        }
        if (insufficient) {
            node.put("emptyReason", INSUFFICIENT_EVIDENCE);
        }
        node.put("verificationStatus", insufficient ? INSUFFICIENT_EVIDENCE : CLASSIFICATION_INFERENCE);
        node.put("conclusionKind", "VULNERABILITY_TRIAGE");
        return node;
    }

    /** Wire-safe map for FindingDto.rootCause (includes optional counterevidence). */
    public static Map<String, Object> toRootCauseMap(ParseResult parsed) {
        if (parsed == null || parsed.rootCause() == null) return Map.of();
        Map<String, Object> map = new LinkedHashMap<>(rootCauseToMap(parsed.rootCause()));
        if (!parsed.counterevidence().isEmpty()) {
            map.put("counterevidence", parsed.counterevidence());
        }
        return Map.copyOf(map);
    }

    public static Map<String, Object> rootCauseToMap(RootCauseAnalysis analysis) {
        if (analysis == null) return Map.of();
        Map<String, Object> map = new LinkedHashMap<>();
        List<Object> steps = new ArrayList<>();
        for (RootCauseAnalysis.AttackStep step : analysis.attackPath()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("layer", step.layer());
            row.put("label", step.label());
            row.put("evidenceRefs", step.evidenceRefs());
            steps.add(Map.copyOf(row));
        }
        map.put("attackPath", List.copyOf(steps));
        map.put("rootCauseStatement", analysis.rootCauseStatement());
        if (!analysis.affectedComponent().isBlank()) {
            map.put("affectedComponent", analysis.affectedComponent());
        }
        if (!analysis.cweId().isBlank()) {
            map.put("cweId", analysis.cweId());
        }
        if (!analysis.fixSuggestion().isBlank()) {
            map.put("fixSuggestion", analysis.fixSuggestion());
        }
        return Map.copyOf(map);
    }

    private static ParseResult insufficient(
            RootCauseAnalysis rootCause,
            List<String> evidenceRefs,
            List<String> counterevidence,
            List<String> rejected) {
        return new ParseResult(rootCause, evidenceRefs, counterevidence, rejected, true);
    }

    private static void writeRootCause(ObjectNode node, RootCauseAnalysis analysis) {
        ArrayNode attackPath = node.putArray("attackPath");
        if (analysis != null) {
            for (RootCauseAnalysis.AttackStep step : analysis.attackPath()) {
                ObjectNode row = attackPath.addObject();
                row.put("layer", step.layer());
                row.put("label", step.label());
                ArrayNode stepRefs = row.putArray("evidenceRefs");
                step.evidenceRefs().forEach(stepRefs::add);
            }
            node.put("rootCauseStatement", analysis.rootCauseStatement());
            if (!analysis.affectedComponent().isBlank()) {
                node.put("affectedComponent", analysis.affectedComponent());
            }
            if (!analysis.cweId().isBlank()) {
                node.put("cweId", analysis.cweId());
            }
            if (!analysis.fixSuggestion().isBlank()) {
                node.put("fixSuggestion", analysis.fixSuggestion());
            }
        } else {
            node.put("rootCauseStatement", "");
        }
    }

    private static List<String> readStringArray(
            JsonNode array, int max, List<String> rejected, String rejectPrefix) {
        List<String> values = new ArrayList<>();
        if (array == null || array.isMissingNode() || array.isNull()) {
            return values;
        }
        if (!array.isArray()) {
            rejected.add(rejectPrefix + "_NOT_ARRAY");
            return values;
        }
        for (JsonNode item : array) {
            if (values.size() >= max) break;
            if (item == null || !item.isTextual()) {
                rejected.add(rejectPrefix + "_INVALID");
                continue;
            }
            String text = item.asText("").trim();
            if (text.isBlank()) {
                rejected.add(rejectPrefix + "_BLANK");
                continue;
            }
            values.add(text);
        }
        return values;
    }

    private static String extractJsonObject(String text) {
        Matcher fenced = FENCED_JSON.matcher(text);
        if (fenced.find()) {
            return fenced.group(1);
        }
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start >= 0 && end > start) {
            String candidate = text.substring(start, end + 1);
            if (candidate.contains("\"rootCause\"") || candidate.contains("\"evidenceRefs\"")) {
                return candidate;
            }
        }
        return text;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? "" : value.asText("").trim();
    }
}
