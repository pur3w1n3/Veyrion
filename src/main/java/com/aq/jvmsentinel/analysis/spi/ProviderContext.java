package com.aq.jvmsentinel.analysis.spi;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Scope-bound context for provider collection. Wrong-scope contributions fail closed.
 */
public record ProviderContext(
        String projectId,
        String artifactDigest,
        String scanId,
        ArtifactDescriptor artifact,
        PreAnalysisResult preAnalysis,
        List<String> entryRoutes,
        ProviderBudget budget
) {
    public ProviderContext {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        if (projectId.isBlank() || artifactDigest.isBlank() || scanId.isBlank()) {
            throw new IllegalArgumentException("projectId/artifactDigest/scanId must not be blank");
        }
        entryRoutes = List.copyOf(entryRoutes == null ? List.of() : entryRoutes);
        budget = budget == null ? ProviderBudget.DEFAULT : budget;
    }

    public Path artifactPath() {
        return artifact == null ? null : artifact.normalizedPath();
    }

    public static ProviderContext of(String projectId, String artifactDigest, String scanId,
                                     ArtifactDescriptor artifact, PreAnalysisResult preAnalysis) {
        List<String> routes = preAnalysis == null ? List.of()
                : preAnalysis.entryCatalog().entries().stream()
                .map(e -> e.route() == null ? "" : e.route())
                .toList();
        return new ProviderContext(projectId, artifactDigest, scanId, artifact, preAnalysis,
                routes, ProviderBudget.DEFAULT);
    }
}
