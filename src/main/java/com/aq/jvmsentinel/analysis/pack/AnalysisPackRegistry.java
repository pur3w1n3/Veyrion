package com.aq.jvmsentinel.analysis.pack;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class AnalysisPackRegistry {
    private static final List<AnalysisPack> PACKS = List.of(
            new BladeJwtCredentialPack(),
            new FlowableDeployExperimentPack());

    private AnalysisPackRegistry() { }

    public static List<AnalysisPack> matching(Path artifactPath, List<String> entryRoutes) {
        List<AnalysisPack> matched = new ArrayList<>();
        for (AnalysisPack pack : PACKS) {
            if (pack.matches(artifactPath, entryRoutes)) matched.add(pack);
        }
        return List.copyOf(matched);
    }

    public static List<AnalysisPack> all() {
        return PACKS;
    }
}
