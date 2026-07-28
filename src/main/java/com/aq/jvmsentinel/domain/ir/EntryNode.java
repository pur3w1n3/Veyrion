package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Entry surface (HTTP, RPC, message, task, …). AUTH-only filter rows are not EntryNodes;
 * they project as {@link GuardNode} and are recorded as a compatibility gap.
 *
 * <p>Stable id: {@code entry:{entryDtoId}} — equals legacy EntryDto.id after the prefix.
 */
public record EntryNode(
        String id,
        String protocol,
        String operation,
        String address,
        String declaringSymbol,
        List<String> inputs,
        List<String> evidenceRefs,
        String provenanceKind,
        String verificationStatus
) implements IrNode {
    public EntryNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        protocol = protocol == null || protocol.isBlank() ? "UNKNOWN" : protocol.trim();
        operation = operation == null ? "" : operation;
        address = address == null ? "" : address;
        declaringSymbol = declaringSymbol == null ? "" : declaringSymbol;
        inputs = List.copyOf(inputs == null ? List.of() : inputs);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "FACT" : provenanceKind;
        verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                ? "STATIC_INFERRED" : verificationStatus;
    }

    @Override
    public String kind() {
        return "ENTRY";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("protocol", protocol);
        map.put("operation", operation);
        map.put("address", address);
        map.put("declaringSymbol", declaringSymbol);
        map.put("inputs", inputs);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        map.put("verificationStatus", verificationStatus);
        return map;
    }
}
