package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Skeleton：从 ArtifactUniverse 标记 well-known  risky dependency name/version pattern。
 */
public final class DependencyVersionDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROPERTY = "RISKY_DEPENDENCY_VERSION";

    private static final List<Pattern> RISKY = List.of(
            Pattern.compile("(?i)commons-collections[-_]3\\.2\\.1"),
            Pattern.compile("(?i)fastjson[-_]1\\.2\\.(2[0-9]|4[0-7]|68|83)"),
            Pattern.compile("(?i)log4j[-_]core[-_]2\\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)([.-]|$)"),
            Pattern.compile("(?i)jackson-databind[-_]2\\.10\\.0")
    );

    @Override
    public String id() {
        return DetectorIds.DEPENDENCY_VERSION;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.DEPENDENCY;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;
        for (ArtifactUniverse.DependencySummary dep : context.universe().dependencies()) {
            if (dep == null || dep.name() == null) continue;
            String name = dep.name();
            for (Pattern pattern : RISKY) {
                if (!pattern.matcher(name).find()) continue;
                out.add(new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-dep-" + context.scanId() + "-" + (++ordinal),
                        context.scanId(),
                        PROPERTY,
                        HypothesisFamily.DEPENDENCY,
                        HypothesisLifecycle.CANDIDATE,
                        id() + "/" + version(),
                        List.of(),
                        List.of(),
                        List.of(),
                        name.toLowerCase(Locale.ROOT),
                        "known-risky-version-heuristic"
                ));
                break;
            }
        }
        return List.copyOf(out);
    }
}
