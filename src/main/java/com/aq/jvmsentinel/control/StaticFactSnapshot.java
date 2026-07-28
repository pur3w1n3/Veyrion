package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Persisted static analysis facts for a scan: bounded BytecodeFactIndex IR plus taint paths,
 * analysis coverage, Artifact Universe (P1-01), optional runtime-loaded class list, and
 * authoritative Evidence Graph wire (P1-02). Stored in {@code taint_graphs.graph_json}
 * (schemaVersion=4 write; schemaVersion=1|2|3|4 read).
 */
public record StaticFactSnapshot(
        String coverageStatus,
        List<BytecodeFactIndex.TaintPath> taintPaths,
        BytecodeFactIndex.AnalysisCoverage analysisCoverage,
        List<BytecodeFactIndex.ClassFact> classes,
        List<BytecodeFactIndex.FieldFact> fields,
        List<BytecodeFactIndex.MethodFact> methods,
        List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
        List<BytecodeFactIndex.CallEdge> callEdges,
        List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics,
        List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph,
        List<String> truncateReasons,
        ArtifactUniverse artifactUniverse,
        List<String> runtimeLoadedClasses,
        Map<String, Object> evidenceGraphWire) {

    public static final int SCHEMA_VERSION = 4;
    public static final String COMPLETE = "COMPLETE";
    public static final String LEGACY_INCOMPLETE = "LEGACY_INCOMPLETE";
    public static final String TRUNCATED = "TRUNCATED";

    public static final int MAX_CLASSES = 500;
    public static final int MAX_FIELDS = 2000;
    public static final int MAX_METHODS = 2000;
    public static final int MAX_MEMBER_ACCESSES = 2000;
    public static final int MAX_CALL_EDGES = 2000;
    public static final int MAX_RESOLVED_CALL_EDGES = 2000;
    public static final int MAX_UNRESOLVED_DYNAMICS = 200;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<List<BytecodeFactIndex.TaintPath>> TAINT_PATH_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.ClassFact>> CLASS_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.FieldFact>> FIELD_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.MethodFact>> METHOD_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.MemberAccessFact>> MEMBER_ACCESS_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.CallEdge>> CALL_EDGE_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.UnresolvedDynamicFact>> UNRESOLVED_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<BytecodeFactIndex.ResolvedCallEdge>> RESOLVED_EDGE_LIST =
            new TypeReference<>() { };
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() { };
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };

    public StaticFactSnapshot {
        Objects.requireNonNull(coverageStatus, "coverageStatus");
        taintPaths = copyList(taintPaths);
        analysisCoverage = analysisCoverage == null
                ? BytecodeFactIndex.AnalysisCoverage.empty() : analysisCoverage;
        classes = copyList(classes);
        fields = copyList(fields);
        methods = copyList(methods);
        memberAccesses = copyList(memberAccesses);
        callEdges = copyList(callEdges);
        unresolvedDynamics = copyList(unresolvedDynamics);
        artifactCallGraph = copyList(artifactCallGraph);
        truncateReasons = copyList(truncateReasons);
        artifactUniverse = artifactUniverse == null ? ArtifactUniverse.empty() : artifactUniverse;
        runtimeLoadedClasses = copyList(runtimeLoadedClasses);
        evidenceGraphWire = evidenceGraphWire == null || evidenceGraphWire.isEmpty()
                ? Map.of() : Map.copyOf(evidenceGraphWire);
    }

    /** Compatibility constructor: empty IR lists (schema v1 shape). */
    public StaticFactSnapshot(
            String coverageStatus,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            BytecodeFactIndex.AnalysisCoverage analysisCoverage) {
        this(coverageStatus, taintPaths, analysisCoverage,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                ArtifactUniverse.empty(), List.of(), Map.of());
    }

    /** Compatibility constructor: schema v2 IR without universe. */
    public StaticFactSnapshot(
            String coverageStatus,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            BytecodeFactIndex.AnalysisCoverage analysisCoverage,
            List<BytecodeFactIndex.ClassFact> classes,
            List<BytecodeFactIndex.FieldFact> fields,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics,
            List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph,
            List<String> truncateReasons) {
        this(coverageStatus, taintPaths, analysisCoverage, classes, fields, methods, memberAccesses,
                callEdges, unresolvedDynamics, artifactCallGraph, truncateReasons,
                ArtifactUniverse.empty(), List.of(), Map.of());
    }

    /** Compatibility constructor: schema v3 IR with universe. */
    public StaticFactSnapshot(
            String coverageStatus,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            BytecodeFactIndex.AnalysisCoverage analysisCoverage,
            List<BytecodeFactIndex.ClassFact> classes,
            List<BytecodeFactIndex.FieldFact> fields,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics,
            List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph,
            List<String> truncateReasons,
            ArtifactUniverse artifactUniverse) {
        this(coverageStatus, taintPaths, analysisCoverage, classes, fields, methods, memberAccesses,
                callEdges, unresolvedDynamics, artifactCallGraph, truncateReasons,
                artifactUniverse, List.of(), Map.of());
    }

    public static StaticFactSnapshot fromBytecodeIndex(BytecodeFactIndex index) {
        return fromBytecodeIndex(index, ArtifactUniverse.empty());
    }

    public static StaticFactSnapshot fromBytecodeIndex(
            BytecodeFactIndex index, ArtifactUniverse universe) {
        Objects.requireNonNull(index, "index");
        ArtifactUniverse artifactUniverse = universe == null ? ArtifactUniverse.empty() : universe;
        List<String> truncateReasons = new ArrayList<>();
        List<BytecodeFactIndex.ClassFact> classes =
                bound(index.classes(), MAX_CLASSES, "classes capped at " + MAX_CLASSES, truncateReasons);
        List<BytecodeFactIndex.FieldFact> fields =
                bound(index.fields(), MAX_FIELDS, "fields capped at " + MAX_FIELDS, truncateReasons);
        List<BytecodeFactIndex.MethodFact> methods =
                bound(index.methods(), MAX_METHODS, "methods capped at " + MAX_METHODS, truncateReasons);
        List<BytecodeFactIndex.MemberAccessFact> memberAccesses = bound(
                index.memberAccesses(), MAX_MEMBER_ACCESSES,
                "memberAccesses capped at " + MAX_MEMBER_ACCESSES, truncateReasons);
        List<BytecodeFactIndex.CallEdge> callEdges = bound(
                index.callEdges(), MAX_CALL_EDGES,
                "callEdges capped at " + MAX_CALL_EDGES, truncateReasons);
        List<BytecodeFactIndex.UnresolvedDynamicFact> unresolved = bound(
                index.unresolvedDynamics(), MAX_UNRESOLVED_DYNAMICS,
                "unresolvedDynamics capped at " + MAX_UNRESOLVED_DYNAMICS, truncateReasons);
        List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph = bound(
                index.artifactCallGraph(), MAX_RESOLVED_CALL_EDGES,
                "artifactCallGraph capped at " + MAX_RESOLVED_CALL_EDGES, truncateReasons);
        if (artifactUniverse.isMaterialized()) {
            for (String reason : artifactUniverse.truncateReasons()) {
                if (reason == null || reason.isBlank()) continue;
                if (!truncateReasons.contains(reason)) {
                    truncateReasons.add(reason);
                }
            }
        }
        List<BytecodeFactIndex.TaintPath> taintPaths = copyList(index.taintPaths());
        boolean analysisComplete = index.analysisCoverage().complete();
        boolean persistenceTruncated = !truncateReasons.isEmpty()
                || (artifactUniverse.isMaterialized() && artifactUniverse.incomplete());
        String status = (analysisComplete && !persistenceTruncated) ? COMPLETE : TRUNCATED;
        return new StaticFactSnapshot(
                status,
                taintPaths,
                index.analysisCoverage(),
                classes,
                fields,
                methods,
                memberAccesses,
                callEdges,
                unresolved,
                artifactCallGraph,
                truncateReasons,
                artifactUniverse,
                List.of(),
                Map.of());
    }

    public StaticFactSnapshot withArtifactUniverse(ArtifactUniverse universe) {
        return new StaticFactSnapshot(
                coverageStatus, taintPaths, analysisCoverage, classes, fields, methods,
                memberAccesses, callEdges, unresolvedDynamics, artifactCallGraph, truncateReasons,
                universe == null ? ArtifactUniverse.empty() : universe,
                runtimeLoadedClasses, evidenceGraphWire);
    }

    public StaticFactSnapshot withRuntimeLoadedClasses(List<String> loaded) {
        List<String> names = copyList(loaded);
        ArtifactUniverse merged = artifactUniverse.withRuntimeDiff(names);
        return new StaticFactSnapshot(
                coverageStatus, taintPaths, analysisCoverage, classes, fields, methods,
                memberAccesses, callEdges, unresolvedDynamics, artifactCallGraph, truncateReasons,
                merged, names, evidenceGraphWire);
    }

    public StaticFactSnapshot withEvidenceGraph(EvidenceGraph graph) {
        Map<String, Object> wire = graph == null ? Map.of() : Map.copyOf(graph.toMap());
        return new StaticFactSnapshot(
                coverageStatus, taintPaths, analysisCoverage, classes, fields, methods,
                memberAccesses, callEdges, unresolvedDynamics, artifactCallGraph, truncateReasons,
                artifactUniverse, runtimeLoadedClasses, wire);
    }

    public Optional<EvidenceGraph> evidenceGraph() {
        if (evidenceGraphWire.isEmpty()) return Optional.empty();
        try {
            return Optional.of(EvidenceGraph.fromMap(evidenceGraphWire));
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    public boolean hasPersistedEvidenceGraph() {
        return evidenceGraph().isPresent();
    }

    /** Universe with any deferred runtime-loaded class diff applied (coverage projection). */
    public ArtifactUniverse effectiveArtifactUniverse() {
        if (runtimeLoadedClasses.isEmpty()) {
            return artifactUniverse;
        }
        return artifactUniverse.withRuntimeDiff(runtimeLoadedClasses);
    }

    public BytecodeFactIndex toBytecodeIndex() {
        return new BytecodeFactIndex(
                classes,
                fields,
                methods,
                memberAccesses,
                callEdges,
                unresolvedDynamics,
                artifactCallGraph,
                taintPaths,
                analysisCoverage);
    }

    /** True when persisted IR includes at least one method fact (schema v2+). */
    public static boolean hasNonEmptyMethodsIr(StaticFactSnapshot snapshot) {
        return snapshot != null && !snapshot.methods().isEmpty();
    }

    public String toJson() {
        try {
            ObjectNode root = JSON.createObjectNode();
            root.put("schemaVersion", SCHEMA_VERSION);
            root.put("coverageStatus", coverageStatus);
            root.set("taintPaths", JSON.valueToTree(taintPaths));
            root.set("analysisCoverage", JSON.valueToTree(analysisCoverage));
            root.set("classes", JSON.valueToTree(classes));
            root.set("fields", JSON.valueToTree(fields));
            root.set("methods", JSON.valueToTree(methods));
            root.set("memberAccesses", JSON.valueToTree(memberAccesses));
            root.set("callEdges", JSON.valueToTree(callEdges));
            root.set("unresolvedDynamics", JSON.valueToTree(unresolvedDynamics));
            root.set("artifactCallGraph", JSON.valueToTree(artifactCallGraph));
            root.set("truncateReasons", JSON.valueToTree(truncateReasons));
            if (artifactUniverse.isMaterialized()) {
                root.set("artifactUniverse", JSON.valueToTree(artifactUniverse));
            }
            if (!runtimeLoadedClasses.isEmpty()) {
                root.set("runtimeLoadedClasses", JSON.valueToTree(runtimeLoadedClasses));
            }
            if (!evidenceGraphWire.isEmpty()) {
                root.set("evidenceGraph", JSON.valueToTree(evidenceGraphWire));
            }
            return JSON.writeValueAsString(root);
        } catch (Exception failure) {
            throw new IllegalStateException("could not serialize StaticFactSnapshot", failure);
        }
    }

    public static StaticFactSnapshot fromJson(String json) {
        Objects.requireNonNull(json, "json");
        try {
            JsonNode root = JSON.readTree(json);
            int version = root.path("schemaVersion").asInt(1);
            if (version < 1 || version > SCHEMA_VERSION) {
                throw new IllegalArgumentException("unsupported static fact schemaVersion: " + version);
            }
            String status = root.path("coverageStatus").asText(LEGACY_INCOMPLETE);
            List<BytecodeFactIndex.TaintPath> paths = root.has("taintPaths")
                    ? JSON.convertValue(root.get("taintPaths"), TAINT_PATH_LIST)
                    : List.of();
            BytecodeFactIndex.AnalysisCoverage coverage = root.has("analysisCoverage")
                    ? JSON.convertValue(root.get("analysisCoverage"), BytecodeFactIndex.AnalysisCoverage.class)
                    : BytecodeFactIndex.AnalysisCoverage.empty();
            if (version == 1) {
                return new StaticFactSnapshot(status, paths, coverage);
            }
            ArtifactUniverse universe = ArtifactUniverse.empty();
            if (version >= 3 && root.has("artifactUniverse") && !root.get("artifactUniverse").isNull()) {
                universe = JSON.convertValue(root.get("artifactUniverse"), ArtifactUniverse.class);
            }
            List<String> runtimeLoaded = version >= 4
                    ? listOrEmpty(root, "runtimeLoadedClasses", STRING_LIST) : List.of();
            Map<String, Object> evidenceWire = Map.of();
            if (version >= 4 && root.has("evidenceGraph") && root.get("evidenceGraph").isObject()) {
                evidenceWire = JSON.convertValue(root.get("evidenceGraph"), MAP_TYPE);
                if (evidenceWire == null) evidenceWire = Map.of();
            }
            return new StaticFactSnapshot(
                    status,
                    paths,
                    coverage,
                    listOrEmpty(root, "classes", CLASS_LIST),
                    listOrEmpty(root, "fields", FIELD_LIST),
                    listOrEmpty(root, "methods", METHOD_LIST),
                    listOrEmpty(root, "memberAccesses", MEMBER_ACCESS_LIST),
                    listOrEmpty(root, "callEdges", CALL_EDGE_LIST),
                    listOrEmpty(root, "unresolvedDynamics", UNRESOLVED_LIST),
                    listOrEmpty(root, "artifactCallGraph", RESOLVED_EDGE_LIST),
                    listOrEmpty(root, "truncateReasons", STRING_LIST),
                    universe,
                    runtimeLoaded,
                    evidenceWire);
        } catch (IllegalArgumentException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("could not deserialize StaticFactSnapshot", failure);
        }
    }

    public static List<BytecodeFactIndex.TaintPath> resolveTaintPaths(
            Optional<StaticFactSnapshot> facts, List<ApiDtos.SinkDto> sinks) {
        return resolveContrastTaintPaths(facts, sinks);
    }

    /**
     * Contrast/PATH taint-path authority.
     * <ul>
     *   <li>When a static-facts row exists ({@code facts.isPresent()}), return persisted
     *       {@code taintPaths} only — never merge empty-step sink stubs, even if the list
     *       is empty or steps are empty under COMPLETE/TRUNCATED.</li>
     *   <li>When no facts row ({@code facts.isEmpty()}), fall back to
     *       {@link ContrastLedger#taintPathsFromSinks}; callers must treat coverage as
     *       {@link #LEGACY_INCOMPLETE}.</li>
     * </ul>
     */
    public static List<BytecodeFactIndex.TaintPath> resolveContrastTaintPaths(
            Optional<StaticFactSnapshot> facts, List<ApiDtos.SinkDto> sinks) {
        if (facts.isEmpty()) {
            return ContrastLedger.taintPathsFromSinks(sinks);
        }
        return facts.get().taintPaths();
    }

    /** Coverage for contrast/PATH consumers: missing facts row is always LEGACY_INCOMPLETE. */
    public static String resolveContrastCoverageStatus(Optional<StaticFactSnapshot> facts) {
        return facts.map(StaticFactSnapshot::coverageStatus).orElse(LEGACY_INCOMPLETE);
    }

    public static boolean hasPersistedSteps(Optional<StaticFactSnapshot> facts) {
        return facts.map(snapshot -> snapshot.taintPaths().stream().anyMatch(path -> !path.steps().isEmpty()))
                .orElse(false);
    }

    public static String taintPathIdFromSink(ApiDtos.SinkDto sink, Map<String, ApiDtos.EvidenceDto> evidence) {
        if (sink == null) return "";
        String fromSource = extractTaintPathToken(sink.source());
        if (!fromSource.isBlank()) return fromSource;
        for (String ref : sink.evidenceRefs() == null ? List.<String>of() : sink.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence == null ? null : evidence.get(ref);
            if (item != null && item.source() != null && item.source().startsWith("classfile-taint:")) {
                return item.source().substring("classfile-taint:".length()).trim();
            }
        }
        return "";
    }

    private static String extractTaintPathToken(String source) {
        if (source == null) return "";
        int at = source.indexOf("taint-path=");
        if (at < 0) return "";
        return source.substring(at + "taint-path=".length()).split("[,\\s;]", 2)[0].trim();
    }

    public static String normalizeClassRef(String owner) {
        return owner == null ? "" : owner.replace('/', '.');
    }

    public static String methodBindingKey(String owner, String method) {
        if (owner == null || method == null || owner.isBlank() || method.isBlank()) return "";
        return normalizeClassRef(owner) + "#" + method;
    }

    public static ApiDtos.EntryDto findEntryForTaintSource(
            List<ApiDtos.EntryDto> entries,
            Map<String, ApiDtos.EvidenceDto> evidence,
            BytecodeFactIndex.TaintPath path) {
        if (path == null || entries == null || entries.isEmpty()) return null;
        String targetKey = methodBindingKey(path.sourceOwner(), path.sourceMethod());
        if (targetKey.isBlank()) return null;
        for (ApiDtos.EntryDto entry : entries) {
            if (targetKey.equals(methodBindingKey(entry.declaringClass(), handlerMethod(entry, evidence)))) {
                return entry;
            }
            if (targetKey.equals(entryBindingKey(entry, evidence))) {
                return entry;
            }
        }
        return null;
    }

    private static String handlerMethod(ApiDtos.EntryDto entry, Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : entry.evidenceRefs() == null ? List.<String>of() : entry.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence == null ? null : evidence.get(ref);
            if (item == null || item.source() == null || !item.source().startsWith("classfile-annotation:")) {
                continue;
            }
            String location = item.source().substring("classfile-annotation:".length());
            int hash = location.indexOf('#');
            if (hash > 0 && hash < location.length() - 1) {
                String method = location.substring(hash + 1);
                int paren = method.indexOf('(');
                return paren < 0 ? method : method.substring(0, paren);
            }
        }
        return entry.method() == null ? "" : entry.method().toLowerCase(Locale.ROOT);
    }

    private static String entryBindingKey(ApiDtos.EntryDto entry, Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : entry.evidenceRefs() == null ? List.<String>of() : entry.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence == null ? null : evidence.get(ref);
            if (item != null && item.source() != null && item.source().startsWith("classfile-annotation:")) {
                return item.source().substring("classfile-annotation:".length());
            }
        }
        return normalizeClassRef(entry.declaringClass());
    }

    private static <T> List<T> bound(List<T> source, int cap, String reason, List<String> truncateReasons) {
        List<T> values = source == null ? List.of() : source;
        if (values.size() <= cap) {
            return List.copyOf(values);
        }
        truncateReasons.add(reason);
        return List.copyOf(values.subList(0, cap));
    }

    private static <T> List<T> copyList(List<T> values) {
        return List.copyOf(values == null ? List.of() : values);
    }

    private static <T> List<T> listOrEmpty(JsonNode root, String field, TypeReference<List<T>> type) {
        if (!root.has(field) || root.get(field).isNull()) {
            return List.of();
        }
        return JSON.convertValue(root.get(field), type);
    }
}
