package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.ParameterConstraint;
import com.aq.jvmsentinel.model.ParameterSpec;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Post-process parameter / flow summaries into {@link ParameterSpec} constraints without rebuilding CFG.
 * Patterns are heuristic and labeled INFERENCE / FLOW_FRAME — never VERIFIED.
 */
public final class BranchConstraintHarvester {
    private static final Pattern EQUALS_LITERAL = Pattern.compile(
            "(?:String\\.)?equals\\s*\\(\\s*\"([^\"]{1,64})\"\\s*\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern MAX_LEN = Pattern.compile(
            "(?:length\\s*(?:\\(\\))?\\s*[<>]=?\\s*|maxLen[=:]\\s*)(\\d{1,4})",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PARSE_INT = Pattern.compile(
            "Integer\\.parseInt|Long\\.parseLong|parseInt\\(", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENUM_VALUES = Pattern.compile(
            "Enum(?:Class)?\\.values\\(\\)|values\\s*=\\s*\\[([^\\]]{1,128})\\]",
            Pattern.CASE_INSENSITIVE);

    private BranchConstraintHarvester() {
    }

    public static List<ParameterSpec> harvest(
            List<String> parameterEncodings, List<String> flowHints) {
        Map<String, ParameterSpec> byName = new LinkedHashMap<>();
        List<String> params = parameterEncodings == null ? List.of() : parameterEncodings;
        for (String encoding : params) {
            ParameterSpec spec = ParameterSpec.fromLegacy(encoding);
            byName.put(spec.name(), enrich(spec, encoding, flowHints));
        }
        if (byName.isEmpty() && flowHints != null) {
            for (String hint : flowHints) {
                if (hint == null) continue;
                Matcher eq = EQUALS_LITERAL.matcher(hint);
                if (eq.find()) {
                    String name = "value";
                    byName.put(name, new ParameterSpec(name, "string", List.of(
                            new ParameterConstraint(ParameterConstraint.ConstraintType.EQUALS,
                                    eq.group(1), "FLOW_FRAME")), "FLOW_FRAME"));
                }
            }
        }
        return List.copyOf(byName.values());
    }

    private static ParameterSpec enrich(ParameterSpec base, String encoding, List<String> flowHints) {
        List<ParameterConstraint> constraints = new ArrayList<>(base.constraints());
        String type = base.type();
        String blob = encoding == null ? "" : encoding;
        if (flowHints != null) {
            for (String hint : flowHints) {
                if (hint != null && hint.toLowerCase(Locale.ROOT).contains(base.name().toLowerCase(Locale.ROOT))) {
                    blob = blob + " " + hint;
                }
            }
        }
        Matcher eq = EQUALS_LITERAL.matcher(blob);
        while (eq.find()) {
            constraints.add(new ParameterConstraint(
                    ParameterConstraint.ConstraintType.EQUALS, eq.group(1), "FLOW_FRAME"));
        }
        Matcher max = MAX_LEN.matcher(blob);
        if (max.find()) {
            constraints.add(new ParameterConstraint(
                    ParameterConstraint.ConstraintType.MAX_LEN, max.group(1), "FLOW_FRAME"));
        }
        if (PARSE_INT.matcher(blob).find()) {
            type = "integer";
            constraints.add(new ParameterConstraint(
                    ParameterConstraint.ConstraintType.TYPE, "integer", "FLOW_FRAME"));
        }
        Matcher enums = ENUM_VALUES.matcher(blob);
        if (enums.find()) {
            String values = enums.groupCount() >= 1 && enums.group(1) != null ? enums.group(1) : "enum";
            constraints.add(new ParameterConstraint(
                    ParameterConstraint.ConstraintType.ENUM, values, "FLOW_FRAME"));
            type = "enum";
        }
        String origin = constraints.stream().anyMatch(c -> "FLOW_FRAME".equals(c.origin()))
                ? "FLOW_FRAME" : base.origin();
        return new ParameterSpec(base.name(), type, constraints, origin);
    }
}
