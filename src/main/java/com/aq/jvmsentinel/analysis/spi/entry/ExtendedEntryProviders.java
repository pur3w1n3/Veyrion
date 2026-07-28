package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.AnalysisProvider;

import java.util.List;

/** P2 skeleton EntryProviders installed via {@code DefaultJvmProviders}. */
public final class ExtendedEntryProviders {
    private ExtendedEntryProviders() {
    }

    public static List<AnalysisProvider> all() {
        return List.of(
                new ServletFilterEntryProvider(),
                new WebFluxEntryProvider(),
                new MessageListenerEntryProvider(),
                new ScheduledEntryProvider(),
                new WebSocketRpcEntryProvider()
        );
    }
}
