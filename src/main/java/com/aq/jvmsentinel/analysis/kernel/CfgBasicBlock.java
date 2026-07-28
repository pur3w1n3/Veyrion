package com.aq.jvmsentinel.analysis.kernel;

import java.util.List;
import java.util.Objects;

/** One bounded basic block in a serializable CFG projection. */
public record CfgBasicBlock(
        int id,
        int startBci,
        int endBci,
        List<String> evidenceRefs,
        List<Integer> successors) {

    public CfgBasicBlock {
        if (id < 0) throw new IllegalArgumentException("id must be non-negative");
        if (startBci < 0 || endBci < startBci) {
            throw new IllegalArgumentException("invalid bci range");
        }
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        successors = List.copyOf(successors == null ? List.of() : successors);
    }

    public CfgBasicBlock withSuccessors(List<Integer> next) {
        return new CfgBasicBlock(id, startBci, endBci, evidenceRefs, next);
    }

    @Override
    public String toString() {
        return "CfgBasicBlock{id=" + id + ",bci=" + startBci + "-" + endBci + "}";
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof CfgBasicBlock that)) return false;
        return id == that.id
                && startBci == that.startBci
                && endBci == that.endBci
                && evidenceRefs.equals(that.evidenceRefs)
                && successors.equals(that.successors);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, startBci, endBci, evidenceRefs, successors);
    }
}
