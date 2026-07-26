package com.aq.jvmsentinel.analysis.pack;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** Framework-specific high-value experiment shapes. Packs never escalate privileges. */
public interface AnalysisPack {
    String id();

    boolean matches(Path artifactPath, List<String> entryRoutes);

    Optional<String> suggestJwtSecret(Path artifactPath);

    List<ExperimentPlan> experimentTemplates(String entrypointRef, IdentityTrack track);
}
