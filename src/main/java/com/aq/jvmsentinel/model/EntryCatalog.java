package com.aq.jvmsentinel.model;

import java.util.List;

public record EntryCatalog(List<Entrypoint> entries, List<Evidence> evidence) {
    public EntryCatalog {
        entries = List.copyOf(entries == null ? List.of() : entries);
        evidence = List.copyOf(evidence == null ? List.of() : evidence);
    }
}
