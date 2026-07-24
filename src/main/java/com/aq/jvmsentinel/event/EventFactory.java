package com.aq.jvmsentinel.event;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class EventFactory {
    private EventFactory() { }

    public static VersionedEvent create(String eventType, int schemaVersion, IdempotencyKey key, String payload, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        return new VersionedEvent(UUID.randomUUID().toString(), eventType, schemaVersion,
                Instant.now(clock), key, payload == null ? "{}" : payload);
    }

    public static VersionedEvent create(String eventType, int schemaVersion, EventContext context,
                                        IdempotencyKey key, String payload, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        return new VersionedEvent(UUID.randomUUID().toString(), eventType, schemaVersion,
                Instant.now(clock), context, key, payload == null ? "{}" : payload);
    }
}
