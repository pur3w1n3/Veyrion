package com.aq.jvmsentinel.event;

import java.util.Objects;

public record IdempotencyKey(String scope, String value) {
    public IdempotencyKey {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(value, "value");
        if (scope.isBlank() || value.isBlank()) throw new IllegalArgumentException("idempotency key cannot be blank");
    }
}
