package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits Artifact Universe nodes and unexpanded coverage gaps. */
public interface ArtifactProvider extends AnalysisProvider {
    List<ProviderContribution.ArtifactNodes> contributeArtifacts(ProviderContext context);
}
