package com.aq.jvmsentinel.domain.coverage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Read-only coverage matrix for a scan (P0-13). Aggregates known gaps; never invents coverage.
 * SUCCESS / COMPLETED must never be interpreted as safe or secure.
 */
public record CoverageMatrix(
        int schemaVersion,
        String scanId,
        ArtifactUniverseSummary artifactUniverseSummary,
        List<NamedCount> entryFamilies,
        CallResolutionCounts callResolution,
        List<DetectorCoverage> detectors,
        DynamicExperimentCoverage dynamicExperiments,
        List<NamedCount> stopReasons,
        GapCounts gaps,
        HonestyFlags honestyFlags,
        String checksum
) {
    public static final int SCHEMA_VERSION = 1;

    public CoverageMatrix {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        Objects.requireNonNull(scanId, "scanId");
        if (scanId.isBlank()) throw new IllegalArgumentException("scanId must not be blank");
        artifactUniverseSummary = artifactUniverseSummary == null
                ? ArtifactUniverseSummary.empty() : artifactUniverseSummary;
        entryFamilies = List.copyOf(entryFamilies == null ? List.of() : entryFamilies);
        callResolution = callResolution == null ? CallResolutionCounts.empty() : callResolution;
        detectors = List.copyOf(detectors == null ? List.of() : detectors);
        dynamicExperiments = dynamicExperiments == null
                ? DynamicExperimentCoverage.empty() : dynamicExperiments;
        stopReasons = List.copyOf(stopReasons == null ? List.of() : stopReasons);
        gaps = gaps == null ? GapCounts.empty() : gaps;
        honestyFlags = honestyFlags == null ? HonestyFlags.defaults() : honestyFlags;
        checksum = checksum == null || checksum.isBlank() ? computeChecksum(
                scanId, artifactUniverseSummary, entryFamilies, callResolution,
                detectors, dynamicExperiments, stopReasons, gaps, honestyFlags) : checksum;
    }

    /** Wire-safe map for API / REPORT context. */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("scanId", scanId);
        map.put("artifactUniverseSummary", artifactUniverseSummary.toMap());
        map.put("entryFamilies", namedCountMaps(entryFamilies));
        map.put("callResolution", callResolution.toMap());
        List<Object> detectorMaps = new ArrayList<>();
        for (DetectorCoverage detector : detectors) {
            detectorMaps.add(detector.toMap());
        }
        map.put("detectors", detectorMaps);
        map.put("dynamicExperiments", dynamicExperiments.toMap());
        map.put("stopReasons", namedCountMaps(stopReasons));
        map.put("gaps", gaps.toMap());
        map.put("honestyFlags", honestyFlags.toMap());
        map.put("checksum", checksum);
        return map;
    }

    /** Short gap summary for REPORT prompts (never claims safe/secure). */
    public String gapsSummaryText(boolean chinese) {
        StringBuilder out = new StringBuilder();
        if (chinese) {
            out.append("COVERAGE_MATRIX_GAPS（未覆盖/缺口；扫描 SUCCESS 不表示安全）：\n");
            out.append("- unknown=").append(gaps.unknown())
                    .append(" unresolved=").append(gaps.unresolved())
                    .append(" truncated=").append(gaps.truncated())
                    .append(" unreached=").append(gaps.unreached()).append('\n');
            out.append("- callResolution DIRECT=").append(callResolution.direct())
                    .append(" CHA=").append(callResolution.cha())
                    .append(" UNRESOLVED=").append(callResolution.unresolved()).append('\n');
            out.append("- detectors coveredFamilies=");
            List<String> covered = new ArrayList<>();
            List<String> missing = new ArrayList<>();
            for (DetectorCoverage d : detectors) {
                if (d.signals() > 0 && d.countedAsCovered()) {
                    covered.add(d.family());
                } else if (!d.countedAsCovered()) {
                    missing.add(d.family() + "(gap)");
                }
            }
            out.append(covered.isEmpty() ? "（无）" : String.join(",", covered));
            if (!missing.isEmpty()) {
                out.append(" gaps=").append(String.join(",", missing));
            }
            out.append('\n');
        } else {
            out.append("COVERAGE_MATRIX_GAPS (gaps only; scan SUCCESS is not safe):\n");
            out.append("- unknown=").append(gaps.unknown())
                    .append(" unresolved=").append(gaps.unresolved())
                    .append(" truncated=").append(gaps.truncated())
                    .append(" unreached=").append(gaps.unreached()).append('\n');
            out.append("- callResolution DIRECT=").append(callResolution.direct())
                    .append(" CHA=").append(callResolution.cha())
                    .append(" UNRESOLVED=").append(callResolution.unresolved()).append('\n');
            out.append("- detectors coveredFamilies=");
            List<String> covered = new ArrayList<>();
            for (DetectorCoverage d : detectors) {
                if (d.signals() > 0 && d.countedAsCovered()) {
                    covered.add(d.family());
                }
            }
            out.append(covered.isEmpty() ? "(none)" : String.join(",", covered)).append('\n');
        }
        return out.toString();
    }

    public static String computeChecksum(
            String scanId,
            ArtifactUniverseSummary artifactUniverseSummary,
            List<NamedCount> entryFamilies,
            CallResolutionCounts callResolution,
            List<DetectorCoverage> detectors,
            DynamicExperimentCoverage dynamicExperiments,
            List<NamedCount> stopReasons,
            GapCounts gaps,
            HonestyFlags honestyFlags) {
        StringBuilder canonical = new StringBuilder();
        canonical.append(scanId).append('|')
                .append(artifactUniverseSummary.canonical()).append('|')
                .append(callResolution.canonical()).append('|')
                .append(gaps.canonical()).append('|')
                .append(dynamicExperiments.canonical()).append('|')
                .append(honestyFlags.neverTreatSuccessAsSafe());
        for (NamedCount item : entryFamilies) {
            canonical.append('|').append(item.name()).append('=').append(item.count());
        }
        for (DetectorCoverage detector : detectors) {
            canonical.append('|').append(detector.canonical());
        }
        for (NamedCount item : stopReasons) {
            canonical.append('|').append(item.name()).append('=').append(item.count());
        }
        return sha256Hex(canonical.toString());
    }

    private static List<Object> namedCountMaps(List<NamedCount> items) {
        List<Object> out = new ArrayList<>();
        for (NamedCount item : items) {
            out.add(item.toMap());
        }
        return out;
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                hex.append(String.format(Locale.ROOT, "%02x", b));
            }
            return hex.toString();
        } catch (Exception failure) {
            throw new IllegalStateException("checksum unavailable", failure);
        }
    }

    public record ArtifactUniverseSummary(
            int classCount,
            int methodCount,
            int fieldCount,
            int dependencyCount,
            boolean incomplete,
            String note
    ) {
        public ArtifactUniverseSummary {
            if (classCount < 0 || methodCount < 0 || fieldCount < 0 || dependencyCount < 0) {
                throw new IllegalArgumentException("counts must be non-negative");
            }
            note = note == null ? "" : note;
        }

        public static ArtifactUniverseSummary empty() {
            return new ArtifactUniverseSummary(0, 0, 0, 0, true, "NO_STATIC_FACTS");
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("classCount", classCount);
            map.put("methodCount", methodCount);
            map.put("fieldCount", fieldCount);
            map.put("dependencyCount", dependencyCount);
            map.put("incomplete", incomplete);
            map.put("note", note);
            return map;
        }

        String canonical() {
            return classCount + "," + methodCount + "," + fieldCount + "," + dependencyCount
                    + "," + incomplete + "," + note;
        }
    }

    public record CallResolutionCounts(int direct, int cha, int unresolved) {
        public CallResolutionCounts {
            if (direct < 0 || cha < 0 || unresolved < 0) {
                throw new IllegalArgumentException("call resolution counts must be non-negative");
            }
        }

        public static CallResolutionCounts empty() {
            return new CallResolutionCounts(0, 0, 0);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("DIRECT", direct);
            map.put("CHA", cha);
            map.put("UNRESOLVED", unresolved);
            // UNRESOLVED is a gap count, never covered.
            map.put("unresolvedIsGap", true);
            return map;
        }

        String canonical() {
            return direct + "," + cha + "," + unresolved;
        }
    }

    public record DetectorCoverage(
            String family,
            String detectorVersion,
            int signals,
            boolean countedAsCovered,
            String note
    ) {
        public DetectorCoverage {
            Objects.requireNonNull(family, "family");
            if (family.isBlank()) throw new IllegalArgumentException("family must not be blank");
            detectorVersion = detectorVersion == null || detectorVersion.isBlank()
                    ? "unknown" : detectorVersion;
            if (signals < 0) throw new IllegalArgumentException("signals must be non-negative");
            note = note == null ? "" : note;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("family", family);
            map.put("detectorVersion", detectorVersion);
            map.put("signals", signals);
            map.put("countedAsCovered", countedAsCovered);
            map.put("note", note);
            return map;
        }

        String canonical() {
            return family + "=" + signals + "/" + countedAsCovered + "/" + detectorVersion;
        }
    }

    public record DynamicExperimentCoverage(
            int pathRunCount,
            int effectiveAttemptCount,
            int unreachedCount,
            List<String> stopReasonSamples
    ) {
        public DynamicExperimentCoverage {
            if (pathRunCount < 0 || effectiveAttemptCount < 0 || unreachedCount < 0) {
                throw new IllegalArgumentException("dynamic counts must be non-negative");
            }
            stopReasonSamples = List.copyOf(stopReasonSamples == null ? List.of() : stopReasonSamples);
        }

        public static DynamicExperimentCoverage empty() {
            return new DynamicExperimentCoverage(0, 0, 0, List.of());
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("pathRunCount", pathRunCount);
            map.put("effectiveAttemptCount", effectiveAttemptCount);
            map.put("unreachedCount", unreachedCount);
            map.put("stopReasonSamples", stopReasonSamples);
            return map;
        }

        String canonical() {
            return pathRunCount + "," + effectiveAttemptCount + "," + unreachedCount
                    + "," + String.join(",", stopReasonSamples);
        }
    }

    public record GapCounts(int unknown, int unresolved, int truncated, int unreached) {
        public GapCounts {
            if (unknown < 0 || unresolved < 0 || truncated < 0 || unreached < 0) {
                throw new IllegalArgumentException("gap counts must be non-negative");
            }
        }

        public static GapCounts empty() {
            return new GapCounts(0, 0, 0, 0);
        }

        public int total() {
            return unknown + unresolved + truncated + unreached;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("unknown", unknown);
            map.put("unresolved", unresolved);
            map.put("truncated", truncated);
            map.put("unreached", unreached);
            map.put("total", total());
            map.put("countedAsCovered", false);
            return map;
        }

        String canonical() {
            return unknown + "," + unresolved + "," + truncated + "," + unreached;
        }
    }

    public record HonestyFlags(boolean neverTreatSuccessAsSafe, boolean gapsNeverCountAsCovered) {
        public static HonestyFlags defaults() {
            return new HonestyFlags(true, true);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("neverTreatSuccessAsSafe", neverTreatSuccessAsSafe);
            map.put("gapsNeverCountAsCovered", gapsNeverCountAsCovered);
            // Explicit: SUCCESS/COMPLETED ≠ safe/secure.
            map.put("scanSuccessMeans", "analysis_finished_not_safe");
            return map;
        }
    }

    public record NamedCount(String name, int count) {
        public NamedCount {
            Objects.requireNonNull(name, "name");
            if (name.isBlank()) throw new IllegalArgumentException("name must not be blank");
            if (count < 0) throw new IllegalArgumentException("count must be non-negative");
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("name", name);
            map.put("count", count);
            return map;
        }
    }
}
