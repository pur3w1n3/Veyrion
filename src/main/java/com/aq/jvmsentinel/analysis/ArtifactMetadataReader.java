package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Bounded, metadata-only reader shared by CLI and Control Plane.
 * It never extracts or executes archive entries.
 */
public final class ArtifactMetadataReader {
    private static final int MAX_ARCHIVE_ENTRIES = 100_000;
    private static final int MAX_CLASS_NAMES = 20_000;
    private static final int MAX_CLASS_BYTES = 4 * 1024 * 1024;
    private static final long MAX_TOTAL_CLASS_BYTES = 64L * 1024 * 1024;
    private static final int MAX_TOTAL_METHODS = 100_000;
    private static final int MAX_TOTAL_PARAMETERS = 100_000;
    private static final int MAX_TOTAL_BYTECODE_FACTS = 1_000_000;
    private static final int MAX_CONFIG_FILES = 256;
    private static final int MAX_CONFIG_LINES = 2_000;
    private static final int MAX_CONFIG_BYTES = 1 * 1024 * 1024;
    private static final long MAX_TOTAL_CONFIG_BYTES = 8L * 1024 * 1024;

    private ArtifactMetadataReader() { }

    public static PreAnalysisInput read(ArtifactDescriptor descriptor) throws IOException {
        if (descriptor == null) throw new IllegalArgumentException("descriptor is required");
        LinkedHashSet<String> classNames = new LinkedHashSet<>();
        List<ClassMetadata> classMetadata = new ArrayList<>();
        List<String> config = new ArrayList<>();
        if (descriptor.type() == ArtifactType.CLASS) {
            String fallbackName = descriptor.normalizedPath().getFileName().toString().replaceFirst("(?i)\\.class$", "");
            if (descriptor.sizeBytes() > MAX_CLASS_BYTES) {
                throw new ArtifactValidationException("classfile exceeds the metadata parsing limit");
            }
            byte[] bytes;
            try (InputStream input = Files.newInputStream(descriptor.normalizedPath())) {
                bytes = input.readNBytes(MAX_CLASS_BYTES + 1);
            }
            if (bytes.length > MAX_CLASS_BYTES) {
                throw new ArtifactValidationException("classfile exceeds the metadata parsing limit");
            }
            ClassMetadata parsed = ClassFileMetadataParser.parse(bytes, fallbackName);
            classMetadata.add(parsed);
            classNames.add(parsed.className());
            return new PreAnalysisInput(descriptor, new ArrayList<>(classNames), config, classMetadata);
        }
        int configFiles = 0;
        long totalConfigBytes = 0;
        long totalClassBytes = 0;
        long totalMethods = 0;
        long totalParameters = 0;
        long totalBytecodeFacts = 0;
        try (ZipFile zip = new ZipFile(descriptor.normalizedPath().toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int entryCount = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                if (++entryCount > MAX_ARCHIVE_ENTRIES) {
                    throw new ArtifactValidationException("archive contains too many entries");
                }
                String name = entry.getName();
                String lowerName = name.toLowerCase(Locale.ROOT);
                if (lowerName.endsWith(".class")) {
                    if (classMetadata.size() >= MAX_CLASS_NAMES) {
                        throw new ArtifactValidationException("archive contains too many class entries");
                    }
                    String fallbackName = normalizeClassName(name);
                    long declaredSize = entry.getSize();
                    if (declaredSize > MAX_CLASS_BYTES) {
                        throw new ArtifactValidationException("classfile entry exceeds the metadata parsing limit");
                    }
                    byte[] bytes;
                    try (InputStream input = zip.getInputStream(entry)) {
                        bytes = input.readNBytes(MAX_CLASS_BYTES + 1);
                    }
                    if (bytes.length > MAX_CLASS_BYTES || totalClassBytes + bytes.length > MAX_TOTAL_CLASS_BYTES) {
                        throw new ArtifactValidationException("classfile metadata exceeds the total parsing limit");
                    }
                    totalClassBytes += bytes.length;
                    ClassMetadata parsed = ClassFileMetadataParser.parse(bytes, fallbackName);
                    totalMethods += parsed.methods().size();
                    for (ClassMetadata.MethodMetadata method : parsed.methods()) {
                        totalParameters += method.parameters().size();
                    }
                    totalBytecodeFacts += bytecodeFactCount(parsed);
                    if (totalMethods > MAX_TOTAL_METHODS || totalParameters > MAX_TOTAL_PARAMETERS) {
                        throw new ArtifactValidationException("classfile metadata contains too many members");
                    }
                    if (totalBytecodeFacts > MAX_TOTAL_BYTECODE_FACTS) {
                        throw new ArtifactValidationException("classfile metadata contains too many bytecode facts");
                    }
                    classMetadata.add(parsed);
                    classNames.add(parsed.className());
                }
                if (lowerName.endsWith(".properties") || lowerName.endsWith(".yml") || lowerName.endsWith(".yaml")) {
                    if (++configFiles > MAX_CONFIG_FILES) {
                        throw new ArtifactValidationException("archive contains too many configuration files");
                    }
                    long declaredSize = entry.getSize();
                    if (declaredSize > MAX_CONFIG_BYTES || declaredSize > MAX_TOTAL_CONFIG_BYTES) {
                        throw new ArtifactValidationException("configuration entry exceeds the limit");
                    }
                    byte[] bytes;
                    try (var input = zip.getInputStream(entry)) {
                        bytes = input.readNBytes(MAX_CONFIG_BYTES + 1);
                    }
                    if (bytes.length > MAX_CONFIG_BYTES || totalConfigBytes + bytes.length > MAX_TOTAL_CONFIG_BYTES) {
                        throw new ArtifactValidationException("configuration data exceeds the limit");
                    }
                    totalConfigBytes += bytes.length;
                    String text = new String(bytes, StandardCharsets.UTF_8);
                    int lineCount = 0;
                    for (String line : text.split("\\R", -1)) {
                        if (++lineCount > MAX_CONFIG_LINES) break;
                        config.add(redactConfiguration(line));
                    }
                }
            }
        }
        return new PreAnalysisInput(descriptor, new ArrayList<>(classNames), config, classMetadata);
    }

    private static String normalizeClassName(String entryName) {
        String normalized = entryName.replace('\\', '/');
        if (normalized.startsWith("BOOT-INF/classes/")) {
            normalized = normalized.substring("BOOT-INF/classes/".length());
        } else if (normalized.startsWith("WEB-INF/classes/")) {
            normalized = normalized.substring("WEB-INF/classes/".length());
        }
        return normalized.substring(0, normalized.length() - 6).replace('/', '.');
    }

    private static long bytecodeFactCount(ClassMetadata metadata) {
        return (metadata.classFact() == null ? 0 : 1L)
                + metadata.fieldFacts().size()
                + metadata.methodFacts().size()
                + metadata.memberAccessFacts().size()
                + metadata.callEdges().size()
                + metadata.unresolvedDynamics().size();
    }

    private static String redactConfiguration(String line) {
        int equals = line.indexOf('=');
        int colon = line.indexOf(':');
        int separator = equals < 0 ? colon : colon < 0 ? equals : Math.min(equals, colon);
        if (separator > 0) {
            String key = line.substring(0, separator).trim();
            if (key.matches("(?i).*(password|passwd|secret|token|credential|private[-_.]?key).*")) {
                return key + line.substring(separator, separator + 1) + "<redacted>";
            }
        }
        return line.replaceAll("(?i)(://[^:/\\s]+:)[^@\\s]+@", "$1<redacted>@");
    }
}
