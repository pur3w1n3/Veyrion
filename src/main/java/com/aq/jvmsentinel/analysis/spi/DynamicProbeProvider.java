package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/**
 * Emit 服务端 gate 的 {@link com.aq.jvmsentinel.model.ExperimentPlan} shape。
 * 说明：Network/command/mount/UID/budget 仍为 control-plane owned。
 */
public interface DynamicProbeProvider extends AnalysisProvider {
    List<ProviderContribution.DynamicProbe> contributeProbes(ProviderContext context);
}
