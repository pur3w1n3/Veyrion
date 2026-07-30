package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Adapter 只读探测上下文：注解 metadata、类名、配置行、可选 archive 路径信号。
 * 永不加载或执行制品类。
 */
public record ExecutorEntryContext(
        ArtifactDescriptor artifact,
        List<String> classNames,
        List<String> configurationLines,
        List<ClassMetadata> classMetadata,
        List<String> archiveEntryNames
) {
    public ExecutorEntryContext {
        classNames = List.copyOf(classNames == null ? List.of() : classNames);
        configurationLines = List.copyOf(configurationLines == null ? List.of() : configurationLines);
        classMetadata = List.copyOf(classMetadata == null ? List.of() : classMetadata);
        archiveEntryNames = List.copyOf(archiveEntryNames == null ? List.of() : archiveEntryNames);
    }

    public static ExecutorEntryContext from(PreAnalysisInput input, List<String> archiveEntryNames) {
        Objects.requireNonNull(input, "input");
        return new ExecutorEntryContext(
                input.artifact(),
                input.classNames(),
                input.configurationLines(),
                input.classMetadata(),
                archiveEntryNames);
    }

    public Path artifactPath() {
        return artifact == null ? null : artifact.normalizedPath();
    }

    public boolean classNameContains(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String needle = token.toLowerCase(Locale.ROOT);
        for (String name : classNames) {
            if (name != null && name.toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        for (ClassMetadata metadata : classMetadata) {
            if (metadata != null && metadata.className() != null
                    && metadata.className().toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        return false;
    }

    public boolean configContains(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String needle = token.toLowerCase(Locale.ROOT);
        for (String line : configurationLines) {
            if (line != null && line.toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        return false;
    }

    public boolean archiveEntryContains(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String needle = token.toLowerCase(Locale.ROOT);
        for (String name : archiveEntryNames) {
            if (name != null && name.toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
