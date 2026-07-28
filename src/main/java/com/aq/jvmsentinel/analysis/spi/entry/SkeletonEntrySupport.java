package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Predicate;

/** Shared helpers for P2 skeleton EntryProviders (empty or fixture-hit). */
final class SkeletonEntrySupport {
    private SkeletonEntrySupport() {
    }

    static BytecodeFactIndex index(ProviderContext context) {
        PreAnalysisResult pre = context == null ? null : context.preAnalysis();
        return pre == null ? BytecodeFactIndex.EMPTY : pre.bytecodeFactIndex();
    }

    static List<ProviderContribution.Entry> fromClassMatches(
            ProviderContext context,
            String providerId,
            String declaredScope,
            String protocol,
            Predicate<BytecodeFactIndex.ClassFact> match,
            String addressPrefix) {
        Objects.requireNonNull(context, "context");
        List<ProviderContribution.Entry> out = new ArrayList<>();
        int ordinal = 0;
        for (BytecodeFactIndex.ClassFact clazz : index(context).classes()) {
            if (clazz == null || !match.test(clazz)) continue;
            String className = clazz.className() == null ? "" : clazz.className().replace('/', '.');
            String entryId = providerId + "-" + (++ordinal) + "-" + sanitize(className);
            EntryNode node = new EntryNode(
                    StableNodeIds.entry(entryId),
                    protocol,
                    "HANDLE",
                    addressPrefix + className,
                    className,
                    List.of(),
                    List.of("ev-" + entryId),
                    "INFERENCE",
                    "STATIC_INFERRED");
            out.add(new ProviderContribution.Entry(
                    providerId, declaredScope, 1,
                    context.projectId(), context.artifactDigest(), context.scanId(), node));
        }
        return List.copyOf(out);
    }

    static List<ProviderContribution.Entry> fromMethodMatches(
            ProviderContext context,
            String providerId,
            String declaredScope,
            String protocol,
            Predicate<BytecodeFactIndex.MethodFact> match,
            String addressPrefix) {
        Objects.requireNonNull(context, "context");
        List<ProviderContribution.Entry> out = new ArrayList<>();
        int ordinal = 0;
        for (BytecodeFactIndex.MethodFact method : index(context).methods()) {
            if (method == null || !match.test(method)) continue;
            String owner = method.owner() == null ? "" : method.owner().replace('/', '.');
            String symbol = owner + "#" + method.name();
            String entryId = providerId + "-" + (++ordinal) + "-" + sanitize(symbol);
            EntryNode node = new EntryNode(
                    StableNodeIds.entry(entryId),
                    protocol,
                    method.name() == null ? "INVOKE" : method.name(),
                    addressPrefix + symbol,
                    symbol,
                    List.of(),
                    List.of("ev-" + entryId),
                    "INFERENCE",
                    "STATIC_INFERRED");
            out.add(new ProviderContribution.Entry(
                    providerId, declaredScope, 1,
                    context.projectId(), context.artifactDigest(), context.scanId(), node));
        }
        return List.copyOf(out);
    }

    static boolean implementsAny(BytecodeFactIndex.ClassFact clazz, String... binaryNames) {
        if (clazz == null) return false;
        String superName = normalize(clazz.superClassName());
        for (String candidate : binaryNames) {
            String needle = normalize(candidate);
            if (needle.isEmpty()) continue;
            if (needle.equals(superName)) return true;
            for (String iface : clazz.interfaces()) {
                if (needle.equals(normalize(iface))) return true;
            }
        }
        return false;
    }

    static boolean classNameHint(String className, String token) {
        String lower = normalize(className).toLowerCase(Locale.ROOT);
        String needle = token == null ? "" : token.toLowerCase(Locale.ROOT);
        return !needle.isEmpty() && lower.contains(needle);
    }

    static boolean methodNameHint(BytecodeFactIndex.MethodFact method, String... tokens) {
        if (method == null || method.name() == null) return false;
        String name = method.name().toLowerCase(Locale.ROOT);
        String owner = normalize(method.owner()).toLowerCase(Locale.ROOT);
        for (String token : tokens) {
            String needle = token == null ? "" : token.toLowerCase(Locale.ROOT);
            if (!needle.isEmpty() && (name.contains(needle) || owner.contains(needle))) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String binary) {
        return binary == null ? "" : binary.replace('.', '/').trim();
    }

    private static String sanitize(String raw) {
        String value = raw == null ? "unknown" : raw.replaceAll("[^A-Za-z0-9_.#-]", "_");
        return value.length() <= 80 ? value : value.substring(0, 80);
    }
}
