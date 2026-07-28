package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/**
 * Emits server-gated {@link com.aq.jvmsentinel.model.ExperimentPlan} shapes.
 * Network, command, mount, UID, and budget remain control-plane owned.
 */
public interface DynamicProbeProvider extends AnalysisProvider {
    List<ProviderContribution.DynamicProbe> contributeProbes(ProviderContext context);
}
