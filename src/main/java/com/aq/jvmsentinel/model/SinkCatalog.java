package com.aq.jvmsentinel.model;

import java.util.List;

public record SinkCatalog(List<Sink> sinks) {
    public SinkCatalog {
        sinks = List.copyOf(sinks == null ? List.of() : sinks);
    }
}
