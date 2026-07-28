package com.aq.jvmsentinel.domain.universe;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bounded Artifact Universe: application / third-party / generated / unknown nodes plus
 * explicit {@link CoverageGap}s (P1-01). Language-neutral; JVM path details live in node ids.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ArtifactUniverse(
        int schemaVersion,
        List<ClassNode> classes,
        List<DependencySummary> dependencies,
        List<ResourceNode> resources,
        List<ConfigNode> configs,
        List<CoverageGap> coverageGaps,
        boolean incomplete,
        List<String> truncateReasons
) {
    public static final int SCHEMA_VERSION = 1;

    public ArtifactUniverse {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        classes = List.copyOf(classes == null ? List.of() : classes);
        dependencies = List.copyOf(dependencies == null ? List.of() : dependencies);
        resources = List.copyOf(resources == null ? List.of() : resources);
        configs = List.copyOf(configs == null ? List.of() : configs);
        coverageGaps = List.copyOf(coverageGaps == null ? List.of() : coverageGaps);
        truncateReasons = List.copyOf(truncateReasons == null ? List.of() : truncateReasons);
    }

    public static final String ABSENT_REASON = "NO_UNIVERSE";

    public static ArtifactUniverse empty() {
        return new ArtifactUniverse(
                SCHEMA_VERSION, List.of(), List.of(), List.of(), List.of(), List.of(), true,
                List.of(ABSENT_REASON));
    }

    /** Not a wire field — Jackson would otherwise emit {@code empty} from the JavaBeans name. */
    @JsonIgnore
    public boolean isEmpty() {
        return classes.isEmpty() && dependencies.isEmpty() && resources.isEmpty()
                && configs.isEmpty() && coverageGaps.isEmpty();
    }

    /** False for the schema-compat sentinel; true once a builder materialized a universe. */
    @JsonIgnore
    public boolean isMaterialized() {
        return !truncateReasons.contains(ABSENT_REASON);
    }

    @JsonIgnore
    public int applicationClassCount() {
        int count = 0;
        for (ClassNode node : classes) {
            if (node.scope() == UniverseScope.APPLICATION) count++;
        }
        return count;
    }

    @JsonIgnore
    public int thirdPartyDependencyCount() {
        return dependencies.size();
    }

    /** Merge extra gaps (runtime diff, multi-version follow-ups) into a new universe. */
    public ArtifactUniverse withAdditionalGaps(Collection<CoverageGap> extraGaps) {
        if (extraGaps == null || extraGaps.isEmpty()) {
            return this;
        }
        LinkedHashMap<String, CoverageGap> byId = new LinkedHashMap<>();
        for (CoverageGap gap : coverageGaps) {
            if (gap != null) byId.put(gap.id(), gap);
        }
        for (CoverageGap gap : extraGaps) {
            if (gap == null) continue;
            byId.putIfAbsent(gap.id(), gap);
        }
        return new ArtifactUniverse(
                schemaVersion, classes, dependencies, resources, configs,
                List.copyOf(byId.values()), incomplete, truncateReasons);
    }

    /**
     * Apply runtime-loaded class diff and return a universe that includes those gaps.
     * Empty/null runtime list is a no-op.
     */
    public ArtifactUniverse withRuntimeDiff(Collection<String> runtimeLoadedClassNames) {
        if (runtimeLoadedClassNames == null || runtimeLoadedClassNames.isEmpty()) {
            return this;
        }
        return withAdditionalGaps(diffWithRuntimeLoadedClasses(runtimeLoadedClassNames));
    }

    /**
     * Minimal hook: diff statically known APPLICATION classes against runtime-loaded names.
     * Returns runtime-only and static-not-loaded gaps (bounded).
     */
    @JsonIgnore
    public List<CoverageGap> diffWithRuntimeLoadedClasses(Collection<String> runtimeLoadedClassNames) {
        Set<String> runtime = normalizeClassSet(runtimeLoadedClassNames);
        Set<String> staticApp = new LinkedHashSet<>();
        for (ClassNode node : classes) {
            if (node.scope() == UniverseScope.APPLICATION) {
                staticApp.add(normalizeClassName(node.className()));
            }
        }
        List<CoverageGap> gaps = new ArrayList<>();
        int ordinal = 0;
        for (String loaded : runtime) {
            if (staticApp.contains(loaded)) continue;
            if (gaps.size() >= 64) break;
            gaps.add(new CoverageGap(
                    "gap-runtime-only-" + (++ordinal),
                    CoverageGap.KIND_RUNTIME_ONLY_CLASS,
                    "runtime loaded class absent from static APPLICATION universe: " + loaded,
                    UniverseScope.UNKNOWN,
                    "RUNTIME_DIFF",
                    "runtime-class:" + loaded));
        }
        for (String known : staticApp) {
            if (runtime.contains(known)) continue;
            if (gaps.size() >= 128) break;
            gaps.add(new CoverageGap(
                    "gap-static-not-loaded-" + (++ordinal),
                    CoverageGap.KIND_STATIC_NOT_LOADED,
                    "static APPLICATION class not observed at runtime: " + known,
                    UniverseScope.APPLICATION,
                    "RUNTIME_DIFF",
                    "static-class:" + known));
        }
        return List.copyOf(gaps);
    }

    @JsonIgnore
    public Map<String, Object> summaryMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("classCount", classes.size());
        map.put("applicationClassCount", applicationClassCount());
        map.put("dependencyCount", dependencies.size());
        map.put("resourceCount", resources.size());
        map.put("configCount", configs.size());
        map.put("coverageGapCount", coverageGaps.size());
        map.put("incomplete", incomplete);
        map.put("truncateReasons", truncateReasons);
        return map;
    }

    private static Set<String> normalizeClassSet(Collection<String> names) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (names == null) return out;
        for (String name : names) {
            if (name == null || name.isBlank()) continue;
            out.add(normalizeClassName(name));
        }
        return out;
    }

    private static String normalizeClassName(String name) {
        return name.replace('/', '.').trim();
    }

    public record ClassNode(
            String className,
            UniverseScope scope,
            String archivePath,
            int methodCount,
            int fieldCount
    ) {
        public ClassNode {
            Objects.requireNonNull(className, "className");
            if (className.isBlank()) throw new IllegalArgumentException("className must not be blank");
            scope = scope == null ? UniverseScope.UNKNOWN : scope;
            archivePath = archivePath == null ? "" : archivePath;
            if (methodCount < 0 || fieldCount < 0) {
                throw new IllegalArgumentException("counts must be non-negative");
            }
        }
    }

    public record DependencySummary(
            String name,
            String digestSha256,
            UniverseScope scope,
            long sizeBytes,
            boolean expanded,
            String note
    ) {
        public DependencySummary {
            Objects.requireNonNull(name, "name");
            if (name.isBlank()) throw new IllegalArgumentException("name must not be blank");
            digestSha256 = digestSha256 == null ? "" : digestSha256.toLowerCase(Locale.ROOT);
            scope = scope == null ? UniverseScope.THIRD_PARTY : scope;
            if (sizeBytes < 0) throw new IllegalArgumentException("sizeBytes must be non-negative");
            note = note == null ? "" : note;
        }
    }

    public record ResourceNode(String path, UniverseScope scope, String kind) {
        public ResourceNode {
            Objects.requireNonNull(path, "path");
            if (path.isBlank()) throw new IllegalArgumentException("path must not be blank");
            scope = scope == null ? UniverseScope.UNKNOWN : scope;
            kind = kind == null || kind.isBlank() ? "RESOURCE" : kind.trim().toUpperCase(Locale.ROOT);
        }
    }

    public record ConfigNode(String path, UniverseScope scope) {
        public ConfigNode {
            Objects.requireNonNull(path, "path");
            if (path.isBlank()) throw new IllegalArgumentException("path must not be blank");
            scope = scope == null ? UniverseScope.APPLICATION : scope;
        }
    }
}
