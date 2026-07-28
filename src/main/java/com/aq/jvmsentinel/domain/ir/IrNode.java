package com.aq.jvmsentinel.domain.ir;

import java.util.List;
import java.util.Map;

/**
 * Sealed Security IR node hierarchy for the Evidence Graph (P1-02).
 *
 * <p>Stable IDs follow {@link StableNodeIds}. Nodes carry evidence refs and provenance
 * but never elevate verification status.
 */
public sealed interface IrNode
        permits ProgramNode, EntryNode, TrustBoundaryNode, EffectNode, GuardNode,
        SanitizerNode, StateNode, ResourceNode, RuntimeObservationNode {

    String id();

    /** Wire kind discriminator (PROGRAM, ENTRY, …). */
    String kind();

    List<String> evidenceRefs();

    String provenanceKind();

    Map<String, Object> toMap();
}
