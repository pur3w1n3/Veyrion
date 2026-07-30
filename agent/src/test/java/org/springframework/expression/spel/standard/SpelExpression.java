package org.springframework.expression.spel.standard;

/** Test stub: SpEL evaluation surface outside application classPrefix. */
public class SpelExpression {
    private final String expression;

    public SpelExpression(String expression) {
        this.expression = expression == null ? "" : expression;
    }

    public Object getValue() {
        return expression;
    }

    public Class<?> getValueType() {
        return String.class;
    }
}
