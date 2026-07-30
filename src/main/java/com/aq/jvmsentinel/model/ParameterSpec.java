package com.aq.jvmsentinel.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 结构化 entry 参数。Legacy {@code List<String>} 编码仍可通过
 * {@link #fromLegacy(String)} 读取。
 */
public record ParameterSpec(
        String name,
        String type,
        List<ParameterConstraint> constraints,
        String origin
) {
    public ParameterSpec {
        Objects.requireNonNull(name, "name");
        type = type == null || type.isBlank() ? "string" : type.toLowerCase(Locale.ROOT);
        constraints = List.copyOf(constraints == null ? List.of() : constraints);
        origin = origin == null || origin.isBlank() ? "INFERRED" : origin;
    }

    public static ParameterSpec fromLegacy(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            return new ParameterSpec("unknown", "string", List.of(), "LEGACY");
        }
        String name = encoded;
        int nameAt = encoded.indexOf("name=");
        if (nameAt >= 0) {
            name = encoded.substring(nameAt + 5).split("[,\\s]", 2)[0].trim();
        } else if (encoded.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) {
            name = encoded;
        }
        if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) name = "param";
        List<ParameterConstraint> constraints = new ArrayList<>();
        String lower = encoded.toLowerCase(Locale.ROOT);
        String type = "string";
        if (lower.contains("type=integer") || lower.contains("type=int") || lower.contains("parseint")) {
            type = "integer";
            constraints.add(new ParameterConstraint(ParameterConstraint.ConstraintType.TYPE, "integer", "LEGACY"));
        }
        if (lower.contains("required=true") || lower.contains("required")) {
            constraints.add(new ParameterConstraint(
                    ParameterConstraint.ConstraintType.REQUIRED, "true", "LEGACY"));
        }
        int maxAt = lower.indexOf("maxlen=");
        if (maxAt >= 0) {
            String digits = encoded.substring(maxAt + 7).split("\\D", 2)[0];
            if (!digits.isBlank()) {
                constraints.add(new ParameterConstraint(
                        ParameterConstraint.ConstraintType.MAX_LEN, digits, "LEGACY"));
            }
        }
        return new ParameterSpec(name, type, constraints,
                encoded.contains("name=") ? "LEGACY" : "LEGACY");
    }

    public String toLegacyEncoding() {
        StringBuilder out = new StringBuilder("name=").append(name)
                .append(", type=").append(type);
        for (ParameterConstraint constraint : constraints) {
            out.append(", ").append(constraint.type().name().toLowerCase(Locale.ROOT))
                    .append('=').append(constraint.literal());
        }
        out.append(" [").append(origin).append(']');
        return out.toString();
    }
}
