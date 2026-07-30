package com.aq.jvmsentinel.artifact;

import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipException;

public final class ArtifactRegistry {
    private static final long DEFAULT_MAX_ARTIFACT_BYTES = 512L * 1024 * 1024;
    private static final int DEFAULT_MAX_ARCHIVE_ENTRIES = 100_000;
    private static final long DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1L * 1024 * 1024 * 1024;

    private final Path allowedRoot;
    private final Clock clock;
    private final long maxArtifactBytes;
    private final int maxArchiveEntries;
    private final long maxArchiveUncompressedBytes;
    private final Map<String, ArtifactDescriptor> byDigest = new ConcurrentHashMap<>();

    public ArtifactRegistry(Path allowedRoot) { this(allowedRoot, Clock.systemUTC()); }

    public ArtifactRegistry(Path allowedRoot, Clock clock) {
        this(allowedRoot, clock, DEFAULT_MAX_ARTIFACT_BYTES, DEFAULT_MAX_ARCHIVE_ENTRIES,
                DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES);
    }

    public ArtifactRegistry(Path allowedRoot, Clock clock, long maxArtifactBytes,
                            int maxArchiveEntries, long maxArchiveUncompressedBytes) {
        Path root = Objects.requireNonNull(allowedRoot, "allowedRoot").toAbsolutePath().normalize();
        this.clock = Objects.requireNonNull(clock, "clock");
        if (maxArtifactBytes <= 0 || maxArchiveEntries <= 0 || maxArchiveUncompressedBytes <= 0) {
            throw new IllegalArgumentException("artifact limits must be positive");
        }
        try {
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("allowed root must be an existing directory");
            }
            this.allowedRoot = root.toRealPath();
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot resolve allowed root", e);
        }
        this.maxArtifactBytes = maxArtifactBytes;
        this.maxArchiveEntries = maxArchiveEntries;
        this.maxArchiveUncompressedBytes = maxArchiveUncompressedBytes;
    }

    public ArtifactDescriptor register(Path input) {
        ArtifactDescriptor descriptor = inspect(input, null, null);
        byDigest.putIfAbsent(descriptor.sha256(), descriptor);
        return byDigest.get(descriptor.sha256());
    }

    /**
     * 应用完整 artifact 校验策略但不发布 descriptor。
     * 用于 upload 原子安装到 managed content storage 之前。
     */
    public ArtifactDescriptor validate(Path input) {
        return inspect(input, null, null);
    }

    /**
     * 校验内部临时名存储的字节，artifact 类型仅由单独校验过的 display filename 推导。
     */
    public ArtifactDescriptor validate(Path input, String fileName) {
        String displayName = Objects.requireNonNull(fileName, "fileName");
        return inspect(input, typeOf(Path.of(displayName)), displayName);
    }

    /**
     * 注册已安装的 managed 副本。与 legacy path 注册不同，
     * managed descriptor 在后续 digest 查找中优先，
     * 避免较早的 client-owned source path 泄漏回 upload 注册。
     */
    public ArtifactDescriptor registerManaged(Path input) {
        return registerManaged(input, null);
    }

    /**
     * 注册 content-addressed managed 副本，同时保留原始 upload/display basename 供 UI 标签。
     */
    public ArtifactDescriptor registerManaged(Path input, String originalFileName) {
        ArtifactDescriptor descriptor = inspect(input, null, originalFileName);
        byDigest.put(descriptor.sha256(), descriptor);
        return descriptor;
    }

    /** 仅用于 backend-managed storage 的 resolved root。 */
    public Path allowedRoot() {
        return allowedRoot;
    }

    public long maxArtifactBytes() {
        return maxArtifactBytes;
    }

    private ArtifactDescriptor inspect(Path input, ArtifactType requestedType, String originalFileName) {
        Objects.requireNonNull(input, "input");
        Path candidate = input.toAbsolutePath().normalize();
        if (!candidate.startsWith(allowedRoot)) {
            throw new ArtifactValidationException("artifact path is outside the allowed root");
        }
        try {
            if (Files.isSymbolicLink(candidate)) {
                throw new ArtifactValidationException("artifact must be a regular, non-symlink file");
            }
            Path path = candidate.toRealPath();
            if (!path.startsWith(allowedRoot) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new ArtifactValidationException("artifact must be a regular file inside the allowed root");
            }
            ArtifactType type = requestedType == null
                    ? (originalFileName != null ? typeOf(Path.of(originalFileName)) : typeOf(path))
                    : requestedType;
            long beforeSize = Files.size(path);
            if (beforeSize > maxArtifactBytes) {
                throw new ArtifactValidationException("artifact exceeds the configured size limit");
            }
            if (type != ArtifactType.CLASS) validateArchive(path);
            String digest = sha256(path);
            long afterSize = Files.size(path);
            if (beforeSize != afterSize) {
                throw new ArtifactValidationException("artifact changed while it was being read");
            }
            final String displayName;
            try {
                displayName = ArtifactDescriptor.sanitizeOriginalFileName(
                        originalFileName != null ? originalFileName : path.getFileName().toString());
            } catch (IllegalArgumentException invalidName) {
                throw new ArtifactValidationException("invalid original file name");
            }
            ArtifactDescriptor descriptor = new ArtifactDescriptor(
                    digest.substring(0, 16), type, path, afterSize, digest, type == ArtifactType.CLASS,
                    Instant.now(clock), displayName);
            return descriptor;
        } catch (IOException e) {
            throw new ArtifactValidationException("cannot read artifact: " + e.getMessage());
        }
    }

    public ArtifactDescriptor findBySha256(String sha256) {
        return sha256 == null ? null : byDigest.get(sha256);
    }

    /** 注册后 source file 若变更则 fail-closed。 */
    public void verifyUnchanged(ArtifactDescriptor descriptor) {
        Objects.requireNonNull(descriptor, "descriptor");
        Path path = descriptor.normalizedPath();
        if (path == null || !path.startsWith(allowedRoot)) {
            throw new ArtifactValidationException("artifact descriptor path is outside the allowed root");
        }
        try {
            Path realPath = path.toRealPath();
            if (!realPath.equals(path) || !realPath.startsWith(allowedRoot)
                    || Files.isSymbolicLink(path) || !Files.isRegularFile(realPath, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(path) != descriptor.sizeBytes()
                    || !descriptor.sha256().equalsIgnoreCase(sha256(realPath))) {
                throw new ArtifactValidationException("artifact changed after registration");
            }
        } catch (IOException e) {
            throw new ArtifactValidationException("cannot verify artifact: " + e.getMessage());
        }
    }

    private static ArtifactType typeOf(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".jar")) return ArtifactType.JAR;
        if (name.endsWith(".war")) return ArtifactType.WAR;
        if (name.endsWith(".class")) return ArtifactType.CLASS;
        throw new ArtifactValidationException("unsupported artifact extension (expected .jar, .war or .class)");
    }

    private void validateArchive(Path path) {
        try (ZipFile ignored = new ZipFile(path.toFile())) {
            int entries = 0;
            long uncompressed = 0;
            var iterator = ignored.entries();
            while (iterator.hasMoreElements()) {
                ZipEntry entry = iterator.nextElement();
                if (++entries > maxArchiveEntries) {
                    throw new ArtifactValidationException("archive contains too many entries");
                }
                long declaredSize = entry.getSize();
                if (declaredSize > 0) {
                    try {
                        uncompressed = Math.addExact(uncompressed, declaredSize);
                    } catch (ArithmeticException overflow) {
                        throw new ArtifactValidationException("archive declared size overflow");
                    }
                    if (uncompressed > maxArchiveUncompressedBytes) {
                        throw new ArtifactValidationException("archive declared uncompressed size exceeds the limit");
                    }
                }
            }
        } catch (ZipException e) {
            throw new ArtifactValidationException("invalid JAR/WAR archive: " + e.getMessage());
        } catch (IOException e) {
            throw new ArtifactValidationException("cannot inspect JAR/WAR archive: " + e.getMessage());
        }
    }

    public static String sha256(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(path)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) != -1) if (read > 0) digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not provide SHA-256", e);
        }
    }
}
