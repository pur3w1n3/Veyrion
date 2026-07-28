package com.aq.jvmsentinel.analysis.kernel;

import java.util.Objects;

/** Directed edge between CFG blocks. */
public record CfgEdge(int fromBlockId, int toBlockId, String kind, String evidenceRef) {

    public static final String FALLTHROUGH = "FALLTHROUGH";
    public static final String CALL_SITE = "CALL_SITE";

    public CfgEdge {
        if (fromBlockId < 0 || toBlockId < 0) {
            throw new IllegalArgumentException("block ids must be non-negative");
        }
        kind = kind == null || kind.isBlank() ? FALLTHROUGH : kind.trim();
        evidenceRef = evidenceRef == null ? "" : evidenceRef;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof CfgEdge that)) return false;
        return fromBlockId == that.fromBlockId
                && toBlockId == that.toBlockId
                && kind.equals(that.kind)
                && evidenceRef.equals(that.evidenceRef);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fromBlockId, toBlockId, kind, evidenceRef);
    }
}
