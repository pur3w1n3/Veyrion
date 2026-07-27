package com.aq.jvmsentinel.model;

import java.util.Objects;

/** Bounded parameter constraint harvested from bytecode flow / annotations. */
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
