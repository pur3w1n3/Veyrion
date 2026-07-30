package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 外部 resource / dependency lifecycle 主体（DB、HTTP client、file、…）。
 *
 * <p>Stable id: {@code resource:{dependencyId}}.
 */
public record ResourceNode(
        String id,
        String resourceKind,
        String target,
        String accessType,
        List<String> evidenceRefs,
        String provenanceKind
) implements IrNode {
    public ResourceNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        resourceKind = resourceKind == null || resourceKind.isBlank() ? "UNKNOWN" : resourceKind.trim();
        target = target == null ? "" : target;
        accessType = accessType == null ? "" : accessType;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "FACT" : provenanceKind;
    }

    @Override
    public String kind() {
        return "RESOURCE";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("resourceKind", resourceKind);
        map.put("target", target);
        map.put("accessType", accessType);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
