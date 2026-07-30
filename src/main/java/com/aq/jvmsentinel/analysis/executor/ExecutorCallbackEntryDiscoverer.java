package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.Evidence;
import com.aq.jvmsentinel.model.ProvenanceKind;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 将 {@link ExecutorEntryAdapter} 候选合成为 {@link Entrypoint}，写入静态 EntryCatalog，
 * 避免「0 entries → 跳过动态」。HTTP 族可被 TracePlan / 探针消费（含后续 context-path 拼接）。
 */
public final class ExecutorCallbackEntryDiscoverer {
    private static final int MAX_ARCHIVE_NAME_ENTRIES = 8_000;
    private static final int MAX_CALLBACK_ENTRIES = 2_000;

    public record Discovery(
            List<Entrypoint> entries,
            List<Evidence> evidence,
            int nextIndex
    ) {
        public Discovery {
            entries = List.copyOf(entries == null ? List.of() : entries);
            evidence = List.copyOf(evidence == null ? List.of() : evidence);
        }
    }

    private ExecutorCallbackEntryDiscoverer() {
    }

    public static Discovery discover(
            PreAnalysisInput input,
            Set<String> existingEntryKeys,
            int startIndex) {
        Objects.requireNonNull(input, "input");
        Set<String> keys = existingEntryKeys == null
                ? new LinkedHashSet<>()
                : new LinkedHashSet<>(existingEntryKeys);
        List<String> archiveNames = archiveEntryNames(input.artifact() == null
                ? null
                : input.artifact().normalizedPath());
        ExecutorEntryContext context = ExecutorEntryContext.from(input, archiveNames);
        List<RuntimeCallbackEntry> candidates = ExecutorEntryAdapterRegistry.discoverAll(context);

        List<Entrypoint> entries = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();
        int index = startIndex;
        for (RuntimeCallbackEntry candidate : candidates) {
            if (entries.size() >= MAX_CALLBACK_ENTRIES) {
                break;
            }
            String key = entryKey(candidate.protocol(), candidate.operation(), candidate.address(),
                    candidate.declaringSymbol());
            if (!keys.add(key)) {
                continue;
            }
            index++;
            String evidenceId = "exec-cb-" + index;
            ProvenanceKind kind = "FACT".equalsIgnoreCase(candidate.provenanceKind())
                    ? ProvenanceKind.FACT
                    : ProvenanceKind.INFERENCE;
            evidence.add(new Evidence(
                    evidenceId,
                    kind,
                    candidate.evidenceSource(),
                    candidate.confidence(),
                    limit(candidate.evidenceSummary())));

            List<String> preconditions = new ArrayList<>(candidate.preconditions());
            if (preconditions.stream().noneMatch(p -> p != null && p.startsWith("framework:"))) {
                preconditions.add("framework:" + candidate.frameworkId());
            }
            preconditions.add("adapter:" + candidate.adapterId());

            String entryId = "entry-exec-" + candidate.frameworkId() + "-" + index;
            entries.add(new Entrypoint(
                    sanitizeId(entryId),
                    candidate.protocol(),
                    candidate.operation(),
                    candidate.address(),
                    candidate.declaringSymbol().isBlank()
                            ? candidate.frameworkId()
                            : candidate.declaringSymbol(),
                    candidate.inputs(),
                    preconditions,
                    List.of(evidenceId),
                    candidate.confidence(),
                    VerificationStatus.STATIC_INFERRED));
        }
        return new Discovery(entries, evidence, index);
    }

    static List<String> archiveEntryNames(Path artifactPath) {
        if (artifactPath == null || !Files.isRegularFile(artifactPath)) {
            return List.of();
        }
        String fileName = artifactPath.getFileName() == null
                ? ""
                : artifactPath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!(fileName.endsWith(".jar") || fileName.endsWith(".war") || fileName.endsWith(".zip"))) {
            return List.of();
        }
        LinkedHashSet<String> names = new LinkedHashSet<>();
        try (ZipFile zip = new ZipFile(artifactPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int count = 0;
            while (entries.hasMoreElements() && count < MAX_ARCHIVE_NAME_ENTRIES) {
                ZipEntry entry = entries.nextElement();
                if (entry == null || entry.isDirectory()) {
                    continue;
                }
                count++;
                String name = entry.getName();
                if (name == null || name.isBlank()) {
                    continue;
                }
                // 仅保留对框架探测有用的路径信号，避免把全量 class 路径灌进 adapter。
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".jar")
                        || lower.contains("xxl-job")
                        || lower.contains("elastic-job")
                        || lower.contains("elasticjob")
                        || lower.contains("actuator")
                        || lower.contains("quartz")
                        || lower.contains("netty")
                        || lower.contains("grpc")) {
                    names.add(name);
                }
            }
        } catch (IOException ignored) {
            return List.of();
        }
        return List.copyOf(names);
    }

    public static String entryKey(String protocol, String method, String route, String declaring) {
        return (protocol == null ? "" : protocol.trim().toUpperCase(Locale.ROOT))
                + "|" + (method == null ? "" : method.trim().toUpperCase(Locale.ROOT))
                + "|" + (route == null ? "" : route.trim())
                + "|" + (declaring == null ? "" : declaring.trim());
    }

    private static String sanitizeId(String raw) {
        String value = raw == null ? "entry-exec" : raw.replaceAll("[^A-Za-z0-9_.#-]", "_");
        return value.length() <= 120 ? value : value.substring(0, 120);
    }

    private static String limit(String value) {
        if (value == null) {
            return "";
        }
        return value.length() <= 512 ? value : value.substring(0, 512);
    }
}
