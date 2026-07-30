package com.aq.jvmsentinel.model;

import java.util.Objects;

/** 从 bytecode flow / annotation 采集的有界 parameter constraint。 */
public record ParameterConstraint(
        ConstraintType type,
        String literal,
        String origin
) {
    public enum ConstraintType {
        EQUALS,
        MAX_LEN,
        ENUM,
        TYPE,
        REQUIRED
    }

    public ParameterConstraint {
        Objects.requireNonNull(type, "type");
        literal = literal == null ? "" : literal;
        origin = origin == null || origin.isBlank() ? "INFERRED" : origin;
        if (literal.length() > 256) literal = literal.substring(0, 256);
    }
}
