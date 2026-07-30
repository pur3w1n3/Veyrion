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
import java.util.zip.ZipInputStream;

/**
 * CLI 与 Control Plane 共享的有界、仅 metadata reader。
 * 永不解压或执行 archive entry。
 *
 * <p>扫描策略（完整运行类路径，一层嵌套）：
 * <ol>
 *   <li>外层 archive：顶层 {@code .class}、{@code BOOT-INF/classes/**}、{@code WEB-INF/classes/**}</li>
 *   <li>嵌套打开 {@code BOOT-INF/lib/*.{jar,war}} 与 {@code WEB-INF/lib/*.{jar,war}} 内 {@code .class}
 *      （流式 {@link ZipInputStream}，一次一个嵌套 jar；不再打开 lib 内的嵌套 jar）</li>
 *   <li>同 FQCN 去重：先到优先——外层（含 BOOT-INF/classes）优先于 lib</li>
 *   <li>跳过 {@code module-info} / {@code package-info}；不跳过含入口信号的框架依赖</li>
 * </ol>
 * 嵌套 lib 触达预算时软停止（保留已解析的应用类）；外层超预算仍 fail-closed。
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
    /** 全部嵌套 lib 合计可解析的 class 上限（软停）。 */
    static final int MAX_NESTED_LIB_CLASSES_TOTAL = 12_000;
    /** 单个嵌套 lib jar 可解析的 class 上限（软停；勿小到跳过 spring-web / xxl-job-core）。 */
    static final int MAX_NESTED_LIB_CLASSES_PER_JAR = 4_000;
    private static final int MAX_NESTED_LIB_JARS = 2_000;

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
        ScanBudget budget = new ScanBudget();
        int configFiles = 0;
        long totalConfigBytes = 0;
        List<ZipEntry> nestedLibs = new ArrayList<>();
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
                if (isNestedLibraryJar(name)) {
                    if (nestedLibs.size() < MAX_NESTED_LIB_JARS) {
                        nestedLibs.add(entry);
                    }
                    continue;
                }
                if (lowerName.endsWith(".class")) {
                    if (shouldSkipClassEntry(name)) {
                        continue;
                    }
                    acceptOuterClass(zip, entry, name, classNames, classMetadata, budget);
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
            for (ZipEntry nested : nestedLibs) {
                if (!budget.canAcceptNestedClass()) {
                    break;
                }
                expandNestedLibOneLayer(zip, nested, classNames, classMetadata, budget);
            }
        }
        return new PreAnalysisInput(descriptor, new ArrayList<>(classNames), config, classMetadata);
    }

    private static void acceptOuterClass(
            ZipFile zip,
            ZipEntry entry,
            String entryName,
            LinkedHashSet<String> classNames,
            List<ClassMetadata> classMetadata,
            ScanBudget budget) throws IOException {
        if (classMetadata.size() >= MAX_CLASS_NAMES) {
            throw new ArtifactValidationException("archive contains too many class entries");
        }
        String fallbackName = normalizeClassName(entryName);
        // 路径名已占用时跳过读字节（同 FQCN 优先保留先到者）。
        if (classNames.contains(fallbackName)) {
            return;
        }
        long declaredSize = entry.getSize();
        if (declaredSize > MAX_CLASS_BYTES) {
            throw new ArtifactValidationException("classfile entry exceeds the metadata parsing limit");
        }
        byte[] bytes;
        try (InputStream input = zip.getInputStream(entry)) {
            bytes = input.readNBytes(MAX_CLASS_BYTES + 1);
        }
        if (bytes.length > MAX_CLASS_BYTES || budget.totalClassBytes + bytes.length > MAX_TOTAL_CLASS_BYTES) {
            throw new ArtifactValidationException("classfile metadata exceeds the total parsing limit");
        }
        ClassMetadata parsed = ClassFileMetadataParser.parse(bytes, fallbackName);
        if (!classNames.add(parsed.className())) {
            return;
        }
        budget.applyHard(parsed, bytes.length);
        classMetadata.add(parsed);
    }

    /**
     * 一层展开嵌套 Boot/WEB-INF lib：流式读取 .class；lib 内再嵌套的 jar/war 不打开。
     */
    private static void expandNestedLibOneLayer(
            ZipFile outer,
            ZipEntry nestedEntry,
            LinkedHashSet<String> classNames,
            List<ClassMetadata> classMetadata,
            ScanBudget budget) {
        int perJar = 0;
        try (InputStream raw = outer.getInputStream(nestedEntry);
             ZipInputStream nested = new ZipInputStream(raw)) {
            ZipEntry inner;
            while ((inner = nested.getNextEntry()) != null) {
                if (inner.isDirectory()) {
                    continue;
                }
                String innerPath = inner.getName().replace('\\', '/');
                String lower = innerPath.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".jar") || lower.endsWith(".war")) {
                    // 一层限制：不递归，避免 fat-in-fat 无限展开。
                    continue;
                }
                if (!lower.endsWith(".class") || shouldSkipClassEntry(innerPath)) {
                    continue;
                }
                if (perJar >= MAX_NESTED_LIB_CLASSES_PER_JAR || !budget.canAcceptNestedClass()) {
                    return;
                }
                if (classMetadata.size() >= MAX_CLASS_NAMES) {
                    return;
                }
                long declaredSize = inner.getSize();
                if (declaredSize > MAX_CLASS_BYTES) {
                    continue;
                }
                byte[] bytes = nested.readNBytes(MAX_CLASS_BYTES + 1);
                if (bytes.length > MAX_CLASS_BYTES
                        || budget.totalClassBytes + bytes.length > MAX_TOTAL_CLASS_BYTES) {
                    return;
                }
                String fallbackName = normalizeClassName(innerPath);
                if (classNames.contains(fallbackName)) {
                    continue;
                }
                ClassMetadata parsed = ClassFileMetadataParser.parse(bytes, fallbackName);
                if (!classNames.add(parsed.className())) {
                    continue;
                }
                if (!budget.tryApplyNested(parsed, bytes.length)) {
                    classNames.remove(parsed.className());
                    return;
                }
                classMetadata.add(parsed);
                perJar++;
            }
        } catch (IOException ignored) {
            // 单个嵌套 jar 损坏时软跳过，不阻断外层与其余 lib。
        }
    }

    static boolean isNestedLibraryJar(String entryName) {
        if (entryName == null || entryName.isBlank()) {
            return false;
        }
        String normalized = entryName.replace('\\', '/');
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (!(lower.endsWith(".jar") || lower.endsWith(".war"))) {
            return false;
        }
        return normalized.startsWith("BOOT-INF/lib/") || normalized.startsWith("WEB-INF/lib/");
    }

    static boolean shouldSkipClassEntry(String entryName) {
        if (entryName == null || entryName.isBlank()) {
            return true;
        }
        String normalized = entryName.replace('\\', '/');
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.endsWith("module-info.class") || lower.endsWith("package-info.class")) {
            return true;
        }
        // 签名块不是 class；多版本目录下的真实业务 class 仍保留（FQCN 去重）。
        return lower.startsWith("meta-inf/") && !lower.contains("/versions/")
                && lower.endsWith(".class");
    }

    private static String normalizeClassName(String entryName) {
        String normalized = entryName.replace('\\', '/');
        if (normalized.startsWith("BOOT-INF/classes/")) {
            normalized = normalized.substring("BOOT-INF/classes/".length());
        } else if (normalized.startsWith("WEB-INF/classes/")) {
            normalized = normalized.substring("WEB-INF/classes/".length());
        } else {
            // 多版本 class：META-INF/versions/N/com/foo/Bar.class → com.foo.Bar
            String marker = "META-INF/versions/";
            if (normalized.regionMatches(true, 0, marker, 0, marker.length())) {
                int slash = normalized.indexOf('/', marker.length());
                if (slash > 0 && slash + 1 < normalized.length()) {
                    normalized = normalized.substring(slash + 1);
                }
            }
        }
        if (normalized.toLowerCase(Locale.ROOT).endsWith(".class")) {
            normalized = normalized.substring(0, normalized.length() - 6);
        }
        return normalized.replace('/', '.');
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

    private static final class ScanBudget {
        long totalClassBytes;
        long totalMethods;
        long totalParameters;
        long totalBytecodeFacts;
        int nestedClassCount;

        boolean canAcceptNestedClass() {
            return nestedClassCount < MAX_NESTED_LIB_CLASSES_TOTAL
                    && totalClassBytes < MAX_TOTAL_CLASS_BYTES
                    && totalMethods < MAX_TOTAL_METHODS
                    && totalParameters < MAX_TOTAL_PARAMETERS
                    && totalBytecodeFacts < MAX_TOTAL_BYTECODE_FACTS;
        }

        void applyHard(ClassMetadata parsed, int byteLength) {
            totalClassBytes += byteLength;
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
        }

        boolean tryApplyNested(ClassMetadata parsed, int byteLength) {
            long methods = parsed.methods().size();
            long parameters = 0;
            for (ClassMetadata.MethodMetadata method : parsed.methods()) {
                parameters += method.parameters().size();
            }
            long facts = bytecodeFactCount(parsed);
            if (nestedClassCount + 1 > MAX_NESTED_LIB_CLASSES_TOTAL
                    || totalClassBytes + byteLength > MAX_TOTAL_CLASS_BYTES
                    || totalMethods + methods > MAX_TOTAL_METHODS
                    || totalParameters + parameters > MAX_TOTAL_PARAMETERS
                    || totalBytecodeFacts + facts > MAX_TOTAL_BYTECODE_FACTS) {
                return false;
            }
            totalClassBytes += byteLength;
            totalMethods += methods;
            totalParameters += parameters;
            totalBytecodeFacts += facts;
            nestedClassCount++;
            return true;
        }
    }
}
