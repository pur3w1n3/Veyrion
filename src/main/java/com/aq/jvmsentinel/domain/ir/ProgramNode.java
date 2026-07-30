package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 程序元素：class、method、field、instruction、config 或 resource symbol。
 *
 * <p>Stable id: {@code program:{elementKind}:{key}} via {@link StableNodeIds}.
 */
public record ProgramNode(
        String id,
        String elementKind,
        String language,
        String symbol,
        String location,
        List<String> evidenceRefs,
        String provenanceKind,
        Map<String, Object> extensions
) implements IrNode {
    public ProgramNode {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(elementKind, "elementKind");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        elementKind = elementKind.trim().toUpperCase(Locale.ROOT);
        language = language == null || language.isBlank() ? "UNKNOWN" : language.trim();
        symbol = symbol == null ? "" : symbol;
        location = location == null ? "" : location;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "FACT" : provenanceKind;
        extensions = extensions == null || extensions.isEmpty()
                ? Map.of() : Map.copyOf(extensions);
    }

    @Override
    public String kind() {
        return "PROGRAM";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("elementKind", elementKind);
        map.put("language", language);
        map.put("symbol", symbol);
        map.put("location", location);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        if (!extensions.isEmpty()) map.put("extensions", extensions);
        return map;
    }
}
