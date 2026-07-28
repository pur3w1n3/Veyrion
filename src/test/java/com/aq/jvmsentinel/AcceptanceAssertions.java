package com.aq.jvmsentinel;

import java.util.concurrent.atomic.AtomicInteger;

/** Thread-safe assertion counter for CI acceptance gate reporting. */
public final class AcceptanceAssertions {
    private static final AtomicInteger COUNT = new AtomicInteger();

    private AcceptanceAssertions() {
    }

    public static void reset() {
        COUNT.set(0);
    }

    public static int get() {
        return COUNT.get();
    }

    public static void record() {
        COUNT.incrementAndGet();
    }
}
