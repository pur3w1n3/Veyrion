package com.aq.fixture;

import org.springframework.expression.spel.standard.SpelExpression;

/**
 * Mirrors SpEL evaluation inside spring-expression (outside classPrefix).
 */
public final class ExpressionEvalFixture {
    private ExpressionEvalFixture() {
    }

    public static void main(String[] args) {
        SpelExpression expression = new SpelExpression("1");
        expression.getValue();
        expression.getValueType();
        System.out.println("ExpressionEvalFixture: PASS");
    }
}
