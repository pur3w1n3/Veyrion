package com.aq.jvmsentinel.analysis.universe;

import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.aq.jvmsentinel.domain.universe.UniverseScope;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Builds a bounded {@link ArtifactUniverse} from archive layout + {@link BytecodeFactIndex}.
 * Nested Boot {@code BOOT-INF/lib} jars are expanded one layer with a per-jar class budget;
 * deeper nesting and budget hits become explicit {@link CoverageGap}s.
 */
public final class ArtifactUniverseBuilder {
    public static final int MAX_CLASSES = 2_000;
    public static final int MAX_DEPENDENCIES = 500;
    public static final int MAX_RESOURCES = 500;
    public static final int MAX_CONFIGS = 256;
    public static final int MAX_GAPS = 500;
    public static final int MAX_ARCHIVE_ENTRIES = 100_000;
    public static final long MAX_NESTED_DIGEST_BYTES = 16L * 1024 * 1024;
    /** Per nested lib jar: max .class entries enumerated in the one-layer expand. */
    public static final int MAX_NESTED_LIB_CLASSES = 256;
    /** Global cap on classes contributed from all nested lib expansions. */
    public static final int MAX_NESTED_LIB_CLASSES_TOTAL = 1_000;

    private ArtifactUniverseBuilder() {
    }

    public static ArtifactUniverse build(
            ArtifactDescriptor descriptor,
            BytecodeFactIndex index,
            List<String> entryProtocols) {
        Objects.requireNonNull(descriptor, "descriptor");
        BytecodeFactIndex facts = index == null ? BytecodeFactIndex.EMPTY : index;
        List<String> protocols = entryProtocols == null ? List.of() : entryProtocols;

        List<ArtifactUniverse.ClassNode> classes = new ArrayList<>();
        List<ArtifactUniverse.DependencySummary> dependencies = new ArrayList<>();
        List<ArtifactUniverse.ResourceNode> resources = new ArrayList<>();
        List<ArtifactUniverse.ConfigNode> configs = new ArrayList<>();
        List<CoverageGap> gaps = new ArrayList<>();
        List<String> truncateReasons = new ArrayList<>();

        Map<String, Counts> methodFieldByClass = countsByClass(facts);

        if (descriptor.type() == ArtifactType.CLASS) {
            for (BytecodeFactIndex.ClassFact classFact : facts.classes()) {
                if (classes.size() >= MAX_CLASSES) {
                    truncateReasons.add("classes capped at " + MAX_CLASSES);
                    break;
                }
                String name = classFact.className().replace('/', '.');
                Counts counts = methodFieldByClass.getOrDefault(name, Counts.ZERO);
                classes.add(new ArtifactUniverse.ClassNode(
                        name, classifyGeneratedOrApplication(name, UniverseScope.APPLICATION),
                        descriptor.normalizedPath().getFileName().toString(),
                        counts.methods, counts.fields));
            }
        } else {
            walkArchive(descriptor, methodFieldByClass, classes, dependencies, resources, configs,
                    gaps, truncateReasons);
            // Ensure fact-index classes not seen in archive walk still appear (e.g. path quirks).
            Set<String> seen = new LinkedHashSet<>();
            for (ArtifactUniverse.ClassNode node : classes) {
                seen.add(node.className());
            }
            for (BytecodeFactIndex.ClassFact classFact : facts.classes()) {
                String name = classFact.className().replace('/', '.');
                if (seen.contains(name)) continue;
                if (classes.size() >= MAX_CLASSES) {
                    addTruncateOnce(truncateReasons, "classes capped at " + MAX_CLASSES);
                    break;
                }
                Counts counts = methodFieldByClass.getOrDefault(name, Counts.ZERO);
                classes.add(new ArtifactUniverse.ClassNode(
                        name, classifyGeneratedOrApplication(name, UniverseScope.APPLICATION),
                        "", counts.methods, counts.fields));
            }
        }

        appendBytecodeGaps(facts, gaps, truncateReasons);
        appendProtocolGaps(protocols, gaps);
        appendMultiVersionClassGaps(classes, gaps, truncateReasons);

        // Gaps are expected coverage honesty signals; incomplete only means budget/IO/analysis stop.
        boolean incomplete = !truncateReasons.isEmpty() || !facts.analysisCoverage().complete();
        if (!facts.analysisCoverage().complete()) {
            for (String reason : facts.analysisCoverage().stopReasons()) {
                if (reason == null || reason.isBlank()) continue;
                addTruncateOnce(truncateReasons, "analysis:" + reason.trim());
            }
            incomplete = true;
        }

        return new ArtifactUniverse(
                ArtifactUniverse.SCHEMA_VERSION,
                classes,
                dependencies,
                resources,
                configs,
                gaps,
                incomplete,
                truncateReasons);
    }

    private static void walkArchive(
            ArtifactDescriptor descriptor,
            Map<String, Counts> methodFieldByClass,
            List<ArtifactUniverse.ClassNode> classes,
            List<ArtifactUniverse.DependencySummary> dependencies,
            List<ArtifactUniverse.ResourceNode> resources,
            List<ArtifactUniverse.ConfigNode> configs,
            List<CoverageGap> gaps,
            List<String> truncateReasons) {
        if (!Files.isRegularFile(descriptor.normalizedPath())) {
            gaps.add(new CoverageGap(
                    "gap-artifact-missing",
                    CoverageGap.KIND_UNKNOWN_RESOURCE,
                    "artifact path not readable for universe walk",
                    UniverseScope.UNKNOWN,
                    "ARTIFACT_MISSING",
                    "artifact:" + descriptor.sha256()));
            return;
        }
        try (ZipFile zip = new ZipFile(descriptor.normalizedPath().toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int entryCount = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                if (++entryCount > MAX_ARCHIVE_ENTRIES) {
                    truncateReasons.add("archive entries capped at " + MAX_ARCHIVE_ENTRIES);
                    gaps.add(new CoverageGap(
                            "gap-archive-budget",
                            CoverageGap.KIND_BUDGET_TRUNCATED,
                            "archive entry walk stopped at budget",
                            UniverseScope.UNKNOWN,
                            "BUDGET",
                            "archive-walk"));
                    break;
                }
                String path = entry.getName().replace('\\', '/');
                String lower = path.toLowerCase(Locale.ROOT);
                UniverseScope pathScope = scopeForArchivePath(path);

                if (lower.endsWith(".class")) {
                    if (classes.size() >= MAX_CLASSES) {
                        addTruncateOnce(truncateReasons, "classes capped at " + MAX_CLASSES);
                        continue;
                    }
                    String className = classNameFromEntry(path);
                    Counts counts = methodFieldByClass.getOrDefault(className, Counts.ZERO);
                    UniverseScope scope = classifyGeneratedOrApplication(className, pathScope);
                    classes.add(new ArtifactUniverse.ClassNode(
                            className, scope, path, counts.methods, counts.fields));
                    continue;
                }

                if (isNestedLibrary(path)) {
                    if (dependencies.size() >= MAX_DEPENDENCIES) {
                        addTruncateOnce(truncateReasons, "dependencies capped at " + MAX_DEPENDENCIES);
                        continue;
                    }
                    String digest = digestEntry(zip, entry, truncateReasons);
                    String name = path.substring(path.lastIndexOf('/') + 1);
                    NestedExpandResult expand = expandNestedLibOneLayer(
                            zip, entry, path, classes, gaps, truncateReasons);
                    String note = expand.expanded()
                            ? ("one-layer expand: classCount=" + expand.classCount()
                            + (expand.truncated() ? "; truncated" : ""))
                            : "nested jar expand failed; treated as unexpanded";
                    dependencies.add(new ArtifactUniverse.DependencySummary(
                            name,
                            digest,
                            UniverseScope.THIRD_PARTY,
                            Math.max(0L, entry.getSize()),
                            expand.expanded(),
                            note));
                    if (!expand.expanded() && gaps.size() < MAX_GAPS) {
                        gaps.add(new CoverageGap(
                                "gap-unexpanded-" + dependencies.size(),
                                CoverageGap.KIND_UNEXPANDED_DEPENDENCY,
                                "BOOT nested dependency not expanded: " + name
                                        + (digest.isBlank() ? "" : " sha256=" + digest),
                                UniverseScope.THIRD_PARTY,
                                "UNEXPANDED",
                                "nested-jar:" + path));
                    }
                    continue;
                }

                if (isConfig(lower)) {
                    if (configs.size() >= MAX_CONFIGS) {
                        addTruncateOnce(truncateReasons, "configs capped at " + MAX_CONFIGS);
                        continue;
                    }
                    configs.add(new ArtifactUniverse.ConfigNode(path, pathScope));
                    continue;
                }

                if (isResourceCandidate(lower, path)) {
                    if (resources.size() >= MAX_RESOURCES) {
                        addTruncateOnce(truncateReasons, "resources capped at " + MAX_RESOURCES);
                        continue;
                    }
                    resources.add(new ArtifactUniverse.ResourceNode(
                            path, pathScope, resourceKind(lower)));
                    if (pathScope == UniverseScope.UNKNOWN && gaps.size() < MAX_GAPS) {
                        gaps.add(new CoverageGap(
                                "gap-unknown-resource-" + resources.size(),
                                CoverageGap.KIND_UNKNOWN_RESOURCE,
                                "resource path scope unknown: " + path,
                                UniverseScope.UNKNOWN,
                                "UNKNOWN_SCOPE",
                                "resource:" + path));
                    }
                }
            }
        } catch (IOException failure) {
            gaps.add(new CoverageGap(
                    "gap-archive-io",
                    CoverageGap.KIND_UNKNOWN_RESOURCE,
                    "archive walk failed: " + failure.getClass().getSimpleName(),
                    UniverseScope.UNKNOWN,
                    "ARCHIVE_IO",
                    "artifact:" + descriptor.sha256()));
            truncateReasons.add("archive walk failed");
        }
    }

    private static void appendBytecodeGaps(
            BytecodeFactIndex facts, List<CoverageGap> gaps, List<String> truncateReasons) {
        int ordinal = 0;
        for (BytecodeFactIndex.UnresolvedDynamicFact dynamic : facts.unresolvedDynamics()) {
            if (gaps.size() >= MAX_GAPS) {
                addTruncateOnce(truncateReasons, "coverageGaps capped at " + MAX_GAPS);
                return;
            }
            String mechanism = dynamic.mechanism() == null
                    ? "" : dynamic.mechanism().trim().toUpperCase(Locale.ROOT);
            String kind = mapDynamicKind(mechanism);
            String evidence = dynamic.evidence() == null ? "" : dynamic.evidence().stableKey();
            gaps.add(new CoverageGap(
                    "gap-dynamic-" + (++ordinal),
                    kind,
                    mechanism + ": " + dynamic.detail(),
                    UniverseScope.APPLICATION,
                    "UNRESOLVED_DYNAMIC",
                    evidence));
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : facts.artifactCallGraph()) {
            if (edge == null || edge.kind() != BytecodeFactIndex.EdgeKind.UNRESOLVED) continue;
            if (gaps.size() >= MAX_GAPS) {
                addTruncateOnce(truncateReasons, "coverageGaps capped at " + MAX_GAPS);
                return;
            }
            String evidence = edge.evidence() == null ? "" : edge.evidence().stableKey();
            gaps.add(new CoverageGap(
                    "gap-call-" + (++ordinal),
                    CoverageGap.KIND_UNRESOLVED_CALL,
                    edge.callerOwner() + "#" + edge.callerName() + " → "
                            + edge.targetOwner() + "#" + edge.targetName()
                            + " (" + edge.limitation() + ")",
                    UniverseScope.APPLICATION,
                    "UNRESOLVED_CALL",
                    evidence));
        }
        if (facts.artifactCallGraph().isEmpty()) {
            for (BytecodeFactIndex.CallEdge edge : facts.callEdges()) {
                if (edge == null || edge.kind() != BytecodeFactIndex.EdgeKind.UNRESOLVED) continue;
                if (gaps.size() >= MAX_GAPS) {
                    addTruncateOnce(truncateReasons, "coverageGaps capped at " + MAX_GAPS);
                    return;
                }
                String evidence = edge.evidence() == null ? "" : edge.evidence().stableKey();
                gaps.add(new CoverageGap(
                        "gap-call-" + (++ordinal),
                        CoverageGap.KIND_UNRESOLVED_CALL,
                        edge.callerOwner() + "#" + edge.callerName() + " → "
                                + edge.targetOwner() + "#" + edge.targetName()
                                + " (" + edge.limitation() + ")",
                        UniverseScope.APPLICATION,
                        "UNRESOLVED_CALL",
                        evidence));
            }
        }
    }

    /**
     * Same binary class name under distinct archive paths → MULTI_VERSION_CLASS gap.
     * Nested BOOT-INF/lib jars are not expanded, so duplicates are typically from
     * BOOT-INF/classes plus a root/META duplicate or repeated class entries.
     */
    private static void appendMultiVersionClassGaps(
            List<ArtifactUniverse.ClassNode> classes,
            List<CoverageGap> gaps,
            List<String> truncateReasons) {
        Map<String, List<ArtifactUniverse.ClassNode>> byName = new LinkedHashMap<>();
        for (ArtifactUniverse.ClassNode node : classes) {
            if (node == null || node.className() == null || node.className().isBlank()) continue;
            byName.computeIfAbsent(node.className(), ignored -> new ArrayList<>()).add(node);
        }
        int ordinal = 0;
        for (Map.Entry<String, List<ArtifactUniverse.ClassNode>> entry : byName.entrySet()) {
            List<ArtifactUniverse.ClassNode> versions = entry.getValue();
            if (versions.size() < 2) continue;
            LinkedHashSet<String> paths = new LinkedHashSet<>();
            for (ArtifactUniverse.ClassNode node : versions) {
                String path = node.archivePath() == null || node.archivePath().isBlank()
                        ? "(index)" : node.archivePath();
                paths.add(path);
            }
            if (paths.size() < 2) continue;
            if (gaps.size() >= MAX_GAPS) {
                addTruncateOnce(truncateReasons, "coverageGaps capped at " + MAX_GAPS);
                return;
            }
            gaps.add(new CoverageGap(
                    "gap-multi-version-" + (++ordinal),
                    CoverageGap.KIND_MULTI_VERSION_CLASS,
                    "class appears under multiple archive paths: " + entry.getKey()
                            + " paths=" + paths,
                    UniverseScope.UNKNOWN,
                    "MULTI_VERSION",
                    "class:" + entry.getKey()));
        }
    }

    private static void appendProtocolGaps(List<String> protocols, List<CoverageGap> gaps) {
        int ordinal = 0;
        Set<String> seen = new LinkedHashSet<>();
        for (String protocol : protocols) {
            NonHttpEntryProtocol.Classification classification = NonHttpEntryProtocol.classify(protocol);
            if (!"UNKNOWN_PROTOCOL".equals(classification.reasonCode())) continue;
            String key = classification.protocol();
            if (!seen.add(key)) continue;
            if (gaps.size() >= MAX_GAPS) return;
            gaps.add(new CoverageGap(
                    "gap-protocol-" + (++ordinal),
                    CoverageGap.KIND_UNKNOWN_PROTOCOL,
                    "entry protocol not modeled for probing: " + key,
                    UniverseScope.UNKNOWN,
                    classification.coverageStatus(),
                    "protocol:" + key));
        }
    }

    private static String mapDynamicKind(String mechanism) {
        if (mechanism.contains("PROXY")) return CoverageGap.KIND_PROXY;
        if (mechanism.contains("REFLECT")) return CoverageGap.KIND_REFLECTION;
        if (mechanism.contains("INVOKEDYNAMIC") || mechanism.contains("INVOKE_DYNAMIC")) {
            return CoverageGap.KIND_INVOKEDYNAMIC;
        }
        return CoverageGap.KIND_UNRESOLVED_CALL;
    }

    private static UniverseScope scopeForArchivePath(String path) {
        String normalized = path.replace('\\', '/');
        if (normalized.startsWith("BOOT-INF/classes/") || normalized.startsWith("WEB-INF/classes/")) {
            return UniverseScope.APPLICATION;
        }
        if (normalized.startsWith("BOOT-INF/lib/") || normalized.startsWith("WEB-INF/lib/")) {
            return UniverseScope.THIRD_PARTY;
        }
        if (normalized.startsWith("org/springframework/boot/loader/")) {
            return UniverseScope.GENERATED;
        }
        if (normalized.startsWith("META-INF/")) {
            return UniverseScope.UNKNOWN;
        }
        if (normalized.endsWith(".class")) {
            return UniverseScope.APPLICATION;
        }
        return UniverseScope.UNKNOWN;
    }

    private static UniverseScope classifyGeneratedOrApplication(String className, UniverseScope base) {
        String name = className == null ? "" : className;
        if (name.contains("$Proxy") || name.contains("$$FastClassBy")
                || name.contains("$$EnhancerBy") || name.contains("CGLIB")
                || name.contains("GeneratedAccessor") || name.startsWith("jdk.proxy")) {
            return UniverseScope.GENERATED;
        }
        if (base == UniverseScope.GENERATED) return UniverseScope.GENERATED;
        if (base == UniverseScope.THIRD_PARTY) return UniverseScope.THIRD_PARTY;
        if (base == UniverseScope.UNKNOWN) return UniverseScope.UNKNOWN;
        return UniverseScope.APPLICATION;
    }

    private static boolean isNestedLibrary(String path) {
        String normalized = path.replace('\\', '/');
        String lower = normalized.toLowerCase(Locale.ROOT);
        return (normalized.startsWith("BOOT-INF/lib/") || normalized.startsWith("WEB-INF/lib/"))
                && (lower.endsWith(".jar") || lower.endsWith(".war"));
    }

    private static boolean isConfig(String lowerPath) {
        return lowerPath.endsWith(".properties")
                || lowerPath.endsWith(".yml")
                || lowerPath.endsWith(".yaml")
                || lowerPath.endsWith(".xml")
                || lowerPath.endsWith(".conf");
    }

    private static boolean isResourceCandidate(String lowerPath, String path) {
        if (lowerPath.endsWith(".jar") || lowerPath.endsWith(".war") || lowerPath.endsWith(".class")) {
            return false;
        }
        if (path.startsWith("BOOT-INF/classes/") || path.startsWith("WEB-INF/classes/")
                || path.startsWith("META-INF/") || path.startsWith("static/")
                || path.startsWith("templates/") || path.startsWith("public/")) {
            return true;
        }
        return lowerPath.endsWith(".json") || lowerPath.endsWith(".txt")
                || lowerPath.endsWith(".html") || lowerPath.endsWith(".js")
                || lowerPath.endsWith(".css");
    }

    private static String resourceKind(String lowerPath) {
        int dot = lowerPath.lastIndexOf('.');
        if (dot < 0 || dot == lowerPath.length() - 1) return "RESOURCE";
        return lowerPath.substring(dot + 1).toUpperCase(Locale.ROOT);
    }

    private static String classNameFromEntry(String entryName) {
        String normalized = entryName.replace('\\', '/');
        if (normalized.startsWith("BOOT-INF/classes/")) {
            normalized = normalized.substring("BOOT-INF/classes/".length());
        } else if (normalized.startsWith("WEB-INF/classes/")) {
            normalized = normalized.substring("WEB-INF/classes/".length());
        }
        if (normalized.toLowerCase(Locale.ROOT).endsWith(".class")) {
            normalized = normalized.substring(0, normalized.length() - 6);
        }
        return normalized.replace('/', '.');
    }

    /**
     * One-layer expand: enumerate .class entries inside a nested Boot/WEB-INF lib jar.
     * Does not open jars nested inside that jar. Class budgets produce explicit gaps.
     */
    private static NestedExpandResult expandNestedLibOneLayer(
            ZipFile outer,
            ZipEntry nestedEntry,
            String nestedPath,
            List<ArtifactUniverse.ClassNode> classes,
            List<CoverageGap> gaps,
            List<String> truncateReasons) {
        int counted = 0;
        boolean truncated = false;
        try (InputStream raw = outer.getInputStream(nestedEntry);
             java.util.zip.ZipInputStream nested = new java.util.zip.ZipInputStream(raw)) {
            ZipEntry inner;
            while ((inner = nested.getNextEntry()) != null) {
                if (inner.isDirectory()) continue;
                String innerPath = inner.getName().replace('\\', '/');
                String lower = innerPath.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".jar") || lower.endsWith(".war")) {
                    if (gaps.size() < MAX_GAPS) {
                        gaps.add(new CoverageGap(
                                "gap-nested-lib-layer-" + gaps.size(),
                                CoverageGap.KIND_UNEXPANDED_DEPENDENCY,
                                "nested jar inside lib not expanded (one-layer only): "
                                        + nestedPath + "!/" + innerPath,
                                UniverseScope.THIRD_PARTY,
                                "NESTED_LAYER_LIMIT",
                                "nested-jar:" + nestedPath + "!/" + innerPath));
                    }
                    continue;
                }
                if (!lower.endsWith(".class")) continue;
                counted++;
                if (counted > MAX_NESTED_LIB_CLASSES) {
                    truncated = true;
                    addTruncateOnce(truncateReasons,
                            "nested lib classes capped at " + MAX_NESTED_LIB_CLASSES + " per jar");
                    break;
                }
                int nestedContributed = countNestedContributed(classes);
                if (nestedContributed >= MAX_NESTED_LIB_CLASSES_TOTAL || classes.size() >= MAX_CLASSES) {
                    truncated = true;
                    addTruncateOnce(truncateReasons,
                            "nested lib classes capped at global " + MAX_NESTED_LIB_CLASSES_TOTAL);
                    break;
                }
                String className = classNameFromEntry(innerPath);
                String archivePath = nestedPath + "!/" + innerPath;
                classes.add(new ArtifactUniverse.ClassNode(
                        className, UniverseScope.THIRD_PARTY, archivePath, 0, 0));
            }
        } catch (IOException failure) {
            addTruncateOnce(truncateReasons, "nested lib expand failed: "
                    + failure.getClass().getSimpleName());
            return new NestedExpandResult(false, 0, false);
        }
        if (truncated && gaps.size() < MAX_GAPS) {
            gaps.add(new CoverageGap(
                    "gap-nested-lib-budget-" + gaps.size(),
                    CoverageGap.KIND_BUDGET_TRUNCATED,
                    "BOOT nested lib class enumeration truncated: " + nestedPath
                            + " counted=" + counted
                            + " perJarCap=" + MAX_NESTED_LIB_CLASSES
                            + " globalCap=" + MAX_NESTED_LIB_CLASSES_TOTAL,
                    UniverseScope.THIRD_PARTY,
                    "NESTED_CLASS_BUDGET",
                    "nested-jar:" + nestedPath));
        }
        return new NestedExpandResult(true, counted, truncated);
    }

    private static int countNestedContributed(List<ArtifactUniverse.ClassNode> classes) {
        int count = 0;
        for (ArtifactUniverse.ClassNode node : classes) {
            if (node.archivePath() != null && node.archivePath().contains("!/")) {
                count++;
            }
        }
        return count;
    }

    private record NestedExpandResult(boolean expanded, int classCount, boolean truncated) {
    }

    private static String digestEntry(ZipFile zip, ZipEntry entry, List<String> truncateReasons) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long total = 0L;
            try (InputStream input = zip.getInputStream(entry)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    total += read;
                    if (total > MAX_NESTED_DIGEST_BYTES) {
                        addTruncateOnce(truncateReasons,
                                "nested jar digest capped at " + MAX_NESTED_DIGEST_BYTES);
                        digest.update(buffer, 0, read);
                        break;
                    }
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception failure) {
            addTruncateOnce(truncateReasons, "nested jar digest failed");
            return "";
        }
    }

    private static Map<String, Counts> countsByClass(BytecodeFactIndex facts) {
        Map<String, Counts> map = new LinkedHashMap<>();
        for (BytecodeFactIndex.MethodFact method : facts.methods()) {
            String owner = method.owner().replace('/', '.');
            map.merge(owner, new Counts(1, 0), Counts::plus);
        }
        for (BytecodeFactIndex.FieldFact field : facts.fields()) {
            String owner = field.owner().replace('/', '.');
            map.merge(owner, new Counts(0, 1), Counts::plus);
        }
        return map;
    }

    private static void addTruncateOnce(List<String> truncateReasons, String reason) {
        if (!truncateReasons.contains(reason)) {
            truncateReasons.add(reason);
        }
    }

    private record Counts(int methods, int fields) {
        static final Counts ZERO = new Counts(0, 0);

        Counts plus(Counts other) {
            return new Counts(methods + other.methods, fields + other.fields);
        }
    }
}
