package com.aq.jvmsentinel.domain.ir;

import java.util.List;
import java.util.Map;

/**
 * Evidence Graph 的 sealed Security IR node 层次（P1-02）。
 *
 * <p>Stable IDs follow {@link StableNodeIds}. Nodes carry evidence refs and provenance
 * 但永不提升 verification status。
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
