package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.analysis.identity.RememberMeCipherHarvester;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 已 surface 的 hardcoded rememberMe/cookie-cipher key 为 CONFIG/TYPESTATE hypothesis。
 * 非 Fastjson / 通用 DESERIALIZATION sink 投影 — category 为 cipher-key config。
 */
public final class HardcodedRememberMeCipherDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROP_HARDCODED_CIPHER = "HARDCODED_REMEMBER_ME_CIPHER_KEY";
    public static final String PROP_UNSAFE_DESER_SURFACE = "UNSAFE_DESERIALIZATION_SURFACE";

    @Override
    public String id() {
        return DetectorIds.REMEMBER_ME_CIPHER;
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

        List<RememberMeCipherHarvester.Hit> hits = context.artifactPath() == null
                ? List.of()
                : RememberMeCipherHarvester.scan(context.artifactPath());

        for (RememberMeCipherHarvester.Hit hit : hits) {
            if (!hit.setCipherKeyPresent()) {
                continue;
            }
            String source = truncate(hit.sourcePath() + " alias=" + hit.alias()
                    + (hit.hasKeyValue() ? "" : " (setCipherKey only)"));
            if (hit.hasKeyValue()) {
                String key = PROP_HARDCODED_CIPHER + "|" + source.toLowerCase(Locale.ROOT);
                if (seen.add(key)) {
                    ordinal++;
                    out.add(hypothesis(context, ordinal, PROP_HARDCODED_CIPHER,
                            HypothesisFamily.CONFIG, source, "remember-me-cipher-key"));
                }
            }
            String deserKey = PROP_UNSAFE_DESER_SURFACE + "|" + source.toLowerCase(Locale.ROOT);
            if (seen.add(deserKey)) {
                ordinal++;
                out.add(hypothesis(context, ordinal, PROP_UNSAFE_DESER_SURFACE,
                        HypothesisFamily.TYPESTATE, source, "remember-me-deserialize-surface"));
            }
        }

        // artifact path 不可用时的 config/evidence fallback（test / legacy）。
        // 主 signal 仍为 setCipherKey；dictionary label 为 secondary。
        if (hits.isEmpty()) {
            for (String line : context.configurationLines()) {
                if (line == null || line.isBlank()) continue;
                boolean setCipher = line.toLowerCase(Locale.ROOT).contains("setcipherkey");
                if (!setCipher) {
                    continue;
                }
                boolean keyHit = false;
                for (var known : RememberMeCipherHarvester.dictionary()) {
                    if (line.contains(known.value())) {
                        keyHit = true;
                        break;
                    }
                }
                if (!keyHit) {
                    for (String candidate : RememberMeCipherHarvester.extractCipherKeyCandidates(line)) {
                        if (!candidate.isBlank()) {
                            keyHit = true;
                            break;
                        }
                    }
                }
                String source = "config:" + truncate(line);
                if (keyHit) {
                    String dedupe = PROP_HARDCODED_CIPHER + "|" + source.toLowerCase(Locale.ROOT);
                    if (seen.add(dedupe)) {
                        ordinal++;
                        out.add(hypothesis(context, ordinal, PROP_HARDCODED_CIPHER,
                                HypothesisFamily.CONFIG, source, "remember-me-cipher-key"));
                    }
                }
                String dedupe = PROP_UNSAFE_DESER_SURFACE + "|" + source.toLowerCase(Locale.ROOT);
                if (seen.add(dedupe)) {
                    ordinal++;
                    out.add(hypothesis(context, ordinal, PROP_UNSAFE_DESER_SURFACE,
                            HypothesisFamily.TYPESTATE, source, "remember-me-deserialize-surface"));
                }
            }
        }
        return List.copyOf(out);
    }

    private static SecurityHypothesis hypothesis(
            DetectorContext context,
            int ordinal,
            String property,
            HypothesisFamily family,
            String source,
            String effect) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-rmc-" + context.scanId() + "-" + ordinal,
                context.scanId(),
                property,
                family,
                HypothesisLifecycle.CANDIDATE,
                DetectorIds.REMEMBER_ME_CIPHER + "/" + VERSION,
                List.of(),
                List.of(),
                List.of(),
                source,
                effect);
    }

    private static String truncate(String value) {
        if (value == null) return "";
        String trimmed = value.trim();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160);
    }
}
