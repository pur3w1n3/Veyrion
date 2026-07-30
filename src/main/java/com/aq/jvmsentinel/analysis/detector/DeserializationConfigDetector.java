package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Skeleton：将 DESERIALIZATION sink 投影为 CONFIG/TYPESTATE-adjacent hypothesis
 * 不发明 fake dataflow sink-none 行。
 */
public final class DeserializationConfigDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROPERTY = "UNSAFE_DESERIALIZATION_SURFACE";

    @Override
    public String id() {
        return DetectorIds.DESERIALIZATION_CONFIG;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.TYPESTATE;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;
        for (ApiDtos.SinkDto sink : context.sinks()) {
            if (sink == null || sink.category() == null) continue;
            if (!"DESERIALIZATION".equalsIgnoreCase(sink.category())) continue;
            String symbol = sink.symbol() == null ? "deserialization" : sink.symbol();
            out.add(new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION,
                    "hyp-deser-" + context.scanId() + "-" + (++ordinal),
                    context.scanId(),
                    PROPERTY,
                    HypothesisFamily.TYPESTATE,
                    HypothesisLifecycle.CANDIDATE,
                    id() + "/" + version(),
                    sink.evidenceRefs(),
                    List.of(),
                    List.of(),
                    truncate(symbol),
                    "deserialize-api"
            ));
        }
        // 亦从 config surface enableDefaultTyping / polymorphic typing hint。
        for (String line : context.configurationLines()) {
            if (line == null) continue;
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("enabledefaulttyping")
                    || lower.contains("activateDefaultTyping".toLowerCase(Locale.ROOT))
                    || (lower.contains("polymorphic") && lower.contains("typing"))) {
                out.add(new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-deser-" + context.scanId() + "-" + (++ordinal),
                        context.scanId(),
                        PROPERTY,
                        HypothesisFamily.TYPESTATE,
                        HypothesisLifecycle.CANDIDATE,
                        id() + "/" + version(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "config:" + truncate(line),
                        "polymorphic-typing"
                ));
            }
        }
        return List.copyOf(out);
    }

    private static String truncate(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }
}
