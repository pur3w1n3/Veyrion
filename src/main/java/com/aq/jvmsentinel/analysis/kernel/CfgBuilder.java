package com.aq.jvmsentinel.analysis.kernel;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * 从 method IR site 构建有界、可序列化 CFG。
 * 以 callEdges / memberAccesses / resolved call-graph evidence 为 block anchor；
 * 不声称完整 branch 或 exception fidelity。
 */
public final class CfgBuilder {
    public static final int GAP_THRESHOLD = 8;
    public static final int BLOCK_CAPACITY = 8;

    private CfgBuilder() {
    }

    public static Optional<CfgGraph> buildForQuery(
            String query,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.ResolvedCallEdge> resolvedEdges) {
        Optional<BytecodeFactIndex.MethodFact> method = resolveMethod(query, methods, callEdges,
                memberAccesses, resolvedEdges);
        return method.map(value -> build(value, callEdges, memberAccesses, resolvedEdges));
    }

    public static CfgGraph build(
            BytecodeFactIndex.MethodFact method,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.ResolvedCallEdge> resolvedEdges) {
        Objects.requireNonNull(method, "method");
        String identity = methodIdentity(method.owner(), method.name(), method.descriptor());
        List<Site> sites = new ArrayList<>();
        for (BytecodeFactIndex.CallEdge edge : nullSafe(callEdges)) {
            collect(identity, edge.evidence(), sites);
        }
        for (BytecodeFactIndex.MemberAccessFact access : nullSafe(memberAccesses)) {
            collect(identity, access.evidence(), sites);
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : nullSafe(resolvedEdges)) {
            collect(identity, edge.evidence(), sites);
        }
        List<String> stopReasons = new ArrayList<>();
        if (sites.isEmpty()) {
            stopReasons.add("CFG_NOT_AVAILABLE");
            return new CfgGraph(CfgGraph.SCHEMA_VERSION, method.owner(), method.name(), method.descriptor(),
                    List.of(), List.of(), "PARTIAL", stopReasons);
        }
        sites.sort(Comparator.comparingInt(Site::bci).thenComparing(Site::evidenceKey));
        List<CfgBasicBlock> draft = splitBlocks(sites, stopReasons);
        List<CfgEdge> edges = new ArrayList<>();
        List<CfgBasicBlock> blocks = new ArrayList<>();
        for (int i = 0; i < draft.size(); i++) {
            CfgBasicBlock block = draft.get(i);
            List<Integer> successors = new ArrayList<>();
            if (i + 1 < draft.size()) {
                int next = draft.get(i + 1).id();
                successors.add(next);
                edges.add(new CfgEdge(block.id(), next, CfgEdge.FALLTHROUGH, ""));
            }
            blocks.add(block.withSuccessors(successors));
        }
        // 标注 call-site adjacency，不发明 observed block 外 target。
        for (int i = 0; i + 1 < blocks.size(); i++) {
            CfgBasicBlock current = blocks.get(i);
            if (current.evidenceRefs().stream().anyMatch(ref -> ref.contains("@bci-"))) {
                edges.add(new CfgEdge(current.id(), blocks.get(i + 1).id(), CfgEdge.CALL_SITE,
                        current.evidenceRefs().get(0)));
            }
        }
        String coverage = stopReasons.isEmpty() ? "COMPLETE" : "PARTIAL";
        return new CfgGraph(CfgGraph.SCHEMA_VERSION, method.owner(), method.name(), method.descriptor(),
                blocks, edges, coverage, stopReasons);
    }

    private static List<CfgBasicBlock> splitBlocks(List<Site> sortedSites, List<String> stopReasons) {
        List<CfgBasicBlock> blocks = new ArrayList<>();
        int blockStart = sortedSites.get(0).bci();
        int blockEnd = blockStart;
        List<String> refs = new ArrayList<>();
        refs.add(sortedSites.get(0).evidenceKey());
        int countInBlock = 1;
        for (int i = 1; i < sortedSites.size(); i++) {
            Site site = sortedSites.get(i);
            boolean gapSplit = site.bci() - blockEnd > GAP_THRESHOLD;
            boolean sizeSplit = countInBlock >= BLOCK_CAPACITY;
            if ((gapSplit || sizeSplit) && blocks.size() < CfgGraph.MAX_BLOCKS) {
                blocks.add(new CfgBasicBlock(blocks.size(), blockStart, blockEnd, refs, List.of()));
                if (blocks.size() >= CfgGraph.MAX_BLOCKS) {
                    stopReasons.add("CFG_BLOCK_BUDGET");
                    return blocks;
                }
                blockStart = site.bci();
                blockEnd = site.bci();
                refs = new ArrayList<>();
                refs.add(site.evidenceKey());
                countInBlock = 1;
            } else if (blocks.size() >= CfgGraph.MAX_BLOCKS) {
                stopReasons.add("CFG_BLOCK_BUDGET");
                return blocks;
            } else {
                blockEnd = site.bci();
                refs.add(site.evidenceKey());
                countInBlock++;
            }
        }
        if (blocks.size() < CfgGraph.MAX_BLOCKS) {
            blocks.add(new CfgBasicBlock(blocks.size(), blockStart, blockEnd, refs, List.of()));
        } else {
            stopReasons.add("CFG_BLOCK_BUDGET");
        }
        return blocks;
    }

    private static Optional<BytecodeFactIndex.MethodFact> resolveMethod(
            String query,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses,
            List<BytecodeFactIndex.ResolvedCallEdge> resolvedEdges) {
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        if (!needle.isEmpty()) {
            for (BytecodeFactIndex.MethodFact method : nullSafe(methods)) {
                String hay = methodIdentity(method.owner(), method.name(), method.descriptor())
                        .toLowerCase(Locale.ROOT);
                if (hay.contains(needle) || method.name().toLowerCase(Locale.ROOT).contains(needle)) {
                    return Optional.of(method);
                }
            }
        }
        // Fallback 到拥有匹配 needle 的 observed site 的首个 method。
        Set<String> candidates = new LinkedHashSet<>();
        for (BytecodeFactIndex.CallEdge edge : nullSafe(callEdges)) {
            if (evidenceMatchesNeedle(edge.evidence(), needle)) {
                candidates.add(methodIdentity(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
            }
        }
        for (BytecodeFactIndex.MemberAccessFact access : nullSafe(memberAccesses)) {
            if (evidenceMatchesNeedle(access.evidence(), needle)) {
                candidates.add(methodIdentity(access.evidence().className(), access.evidence().methodName(),
                        access.evidence().methodDescriptor()));
            }
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : nullSafe(resolvedEdges)) {
            if (evidenceMatchesNeedle(edge.evidence(), needle)) {
                candidates.add(methodIdentity(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
            }
        }
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        String first = candidates.iterator().next();
        for (BytecodeFactIndex.MethodFact method : nullSafe(methods)) {
            if (methodIdentity(method.owner(), method.name(), method.descriptor()).equals(first)) {
                return Optional.of(method);
            }
        }
        int hash = first.indexOf('#');
        int desc = first.indexOf('(', Math.max(hash, 0));
        if (hash > 0 && desc > hash) {
            return Optional.of(new BytecodeFactIndex.MethodFact(
                    first.substring(0, hash),
                    first.substring(hash + 1, desc),
                    first.substring(desc),
                    0,
                    "kernel:synthetic-method:" + first));
        }
        return Optional.empty();
    }

    private static boolean evidenceMatchesNeedle(BytecodeFactIndex.InstructionEvidence evidence, String needle) {
        if (evidence == null || evidence.bytecodeOffset() < 0) return false;
        if (needle.isEmpty()) return true;
        return evidence.stableKey().toLowerCase(Locale.ROOT).contains(needle)
                || evidence.methodName().toLowerCase(Locale.ROOT).contains(needle);
    }

    private static void collect(String identity, BytecodeFactIndex.InstructionEvidence evidence, List<Site> sites) {
        if (evidence == null || evidence.bytecodeOffset() < 0) return;
        if (!methodIdentity(evidence.className(), evidence.methodName(), evidence.methodDescriptor())
                .equals(identity)) {
            return;
        }
        sites.add(new Site(evidence.bytecodeOffset(), evidence.stableKey()));
    }

    public static String methodIdentity(String owner, String name, String descriptor) {
        return (owner == null ? "" : owner.replace('.', '/'))
                + "#" + (name == null ? "" : name)
                + (descriptor == null ? "" : descriptor);
    }

    private static <T> List<T> nullSafe(List<T> values) {
        return values == null ? List.of() : values;
    }

    private record Site(int bci, String evidenceKey) {
        private Site {
            evidenceKey = evidenceKey == null ? "" : evidenceKey;
        }
    }
}
