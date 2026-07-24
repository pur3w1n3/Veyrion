package com.aq.jvmsentinel.event;

import java.time.Instant;
import java.util.Objects;

public record VersionedEvent(String eventId, String eventType, int schemaVersion, Instant occurredAt,
                             EventContext context, IdempotencyKey idempotencyKey, String payload) {
    public VersionedEvent(String eventId, String eventType, int schemaVersion, Instant occurredAt,
                          IdempotencyKey idempotencyKey, String payload) {
        this(eventId, eventType, schemaVersion, occurredAt, null, idempotencyKey, payload);
    }

    public VersionedEvent {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(payload, "payload");
        if (eventId.isBlank() || eventType.isBlank() || schemaVersion <= 0) {
            throw new IllegalArgumentException("event identifiers and schemaVersion are required");
        }
        if (schemaVersion >= 2 && context == null) {
            throw new IllegalArgumentException("schemaVersion >= 2 requires event context");
        }
    }
}
