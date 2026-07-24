package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.util.List;
import java.util.Objects;

public record PreAnalysisInput(ArtifactDescriptor artifact, List<String> classNames,
                               List<String> configurationLines, List<ClassMetadata> classMetadata) {
    public PreAnalysisInput {
        Objects.requireNonNull(artifact, "artifact");
        classNames = List.copyOf(classNames == null ? List.of() : classNames);
        configurationLines = List.copyOf(configurationLines == null ? List.of() : configurationLines);
        classMetadata = List.copyOf(classMetadata == null ? List.of() : classMetadata);
    }

    /** Compatibility constructor for callers that only provide legacy name/config metadata. */
    public PreAnalysisInput(ArtifactDescriptor artifact, List<String> classNames, List<String> configurationLines) {
        this(artifact, classNames, configurationLines, List.of());
    }
}
