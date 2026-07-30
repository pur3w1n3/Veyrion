package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 说明：JWT/crypto/dangerous configuration 启发式（P1-05）。
 * 复用 AUTH_GAP/JWT sink signal 与 redacted configuration 行；永不发明 sink-none。
 */
public final class DangerousConfigDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROP_JWT_ALG_NONE = "JWT_ALG_NONE";
    public static final String PROP_SENSITIVE_CONFIG = "SENSITIVE_CONFIG_MATERIAL";
    public static final String PROP_JWT_SECRET_CONFIG = "JWT_SECRET_CONFIG";

    private static final Pattern ALG_NONE = Pattern.compile(
            "(?i)(alg(orithm)?\\s*[=:]\\s*none|\"alg\"\\s*:\\s*\"none\"|jwt[^\\n]{0,40}none)");
    private static final Pattern SENSITIVE_KEY = Pattern.compile(
            "(?i).*(password|passwd|secret|token|credential|private[-_.]?key).*=\\s*<redacted>");
    private static final Pattern JWT_SECRET_LINE = Pattern.compile(
            "(?i).*(jwt|token).*(secret|key|signing).*=.*");

    @Override
    public String id() {
        return DetectorIds.DANGEROUS_CONFIG;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.CONFIG;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int ordinal = 0;

        for (String line : context.configurationLines()) {
            if (line == null || line.isBlank()) continue;
            if (ALG_NONE.matcher(line).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_JWT_ALG_NONE,
                        "config:" + truncate(line), "jwt-alg-none", List.of());
            }
            if (SENSITIVE_KEY.matcher(line).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_SENSITIVE_CONFIG,
                        "config:" + truncate(line), "plaintext-or-embedded-secret", List.of());
            }
            if (JWT_SECRET_LINE.matcher(line).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_JWT_SECRET_CONFIG,
                        "config:" + truncate(line), "jwt-secret-material", List.of());
            }
        }

        for (ApiDtos.EvidenceDto evidence : context.evidence().values()) {
            if (evidence == null) continue;
            String summary = evidence.summary() == null ? "" : evidence.summary();
            String source = evidence.source() == null ? "" : evidence.source();
            String blob = summary + "\n" + source;
            List<String> refs = List.of(evidence.evidenceId());
            if (ALG_NONE.matcher(blob).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_JWT_ALG_NONE,
                        "evidence:" + evidence.evidenceId(), "jwt-alg-none", refs);
            }
            if (SENSITIVE_KEY.matcher(blob).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_SENSITIVE_CONFIG,
                        "evidence:" + evidence.evidenceId(), "plaintext-or-embedded-secret", refs);
            }
        }

        // 复用 JWT sink presence 为 CONFIG family signal（非 DATAFLOW / 非 sink-none）。
        for (ApiDtos.SinkDto sink : context.sinks()) {
            if (sink == null || sink.category() == null) continue;
            if (!"JWT".equalsIgnoreCase(sink.category())) continue;
            String symbol = sink.symbol() == null ? "" : sink.symbol();
            String source = sink.source() == null ? "" : sink.source();
            String blob = symbol + "\n" + source;
            if (ALG_NONE.matcher(blob).find()) {
                ordinal = add(out, seen, context, ++ordinal, PROP_JWT_ALG_NONE,
                        truncate(symbol.isBlank() ? source : symbol), "jwt-alg-none",
                        sink.evidenceRefs());
            } else if (source.toLowerCase(Locale.ROOT).contains("configuration")
                    || source.toLowerCase(Locale.ROOT).contains("secret")
                    || source.toLowerCase(Locale.ROOT).contains("key")) {
                ordinal = add(out, seen, context, ++ordinal, PROP_JWT_SECRET_CONFIG,
                        truncate(symbol.isBlank() ? source : symbol), "jwt-secret-material",
                        sink.evidenceRefs());
            }
        }

        return List.copyOf(out);
    }

    private int add(List<SecurityHypothesis> out,
                    Set<String> seen,
                    DetectorContext context,
                    int ordinal,
                    String property,
                    String source,
                    String effect,
                    List<String> refs) {
        String key = property + "|" + source.toLowerCase(Locale.ROOT) + "|" + effect;
        if (!seen.add(key)) {
            return ordinal - 1;
        }
        out.add(new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-cfg-" + context.scanId() + "-" + ordinal,
                context.scanId(),
                property,
                HypothesisFamily.CONFIG,
                HypothesisLifecycle.CANDIDATE,
                id() + "/" + version(),
                refs == null ? List.of() : refs,
                List.of(),
                List.of(),
                source,
                effect
        ));
        return ordinal;
    }

    private static String truncate(String value) {
        if (value == null) return "";
        String trimmed = value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }
}
