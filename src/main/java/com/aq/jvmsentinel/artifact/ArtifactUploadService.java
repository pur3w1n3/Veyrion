package com.aq.jvmsentinel.artifact;

import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 有界、顺序的 upload staging，用于 backend-managed JVM artifact。
 *
 * <p>Session 元数据可由 Control Plane 持久化。字节留在受控 staging 目录，
 * 仅在 path、size、offset 与 expiry 校验通过后恢复。</p>
 */
public final class ArtifactUploadService {
    public static final int RECOMMENDED_CHUNK_BYTES = 1 * 1024 * 1024;
    public static final int MAX_CHUNK_BYTES = 4 * 1024 * 1024;
    private static final int DEFAULT_MAX_SESSIONS = 256;
    private static final long DEFAULT_MAX_DECLARED_BYTES = 2L * 1024 * 1024 * 1024;
    private static final Duration DEFAULT_TTL = Duration.ofHours(1);

    private final ArtifactRegistry registry;
    private final Clock clock;
    private final int maxSessions;
    private final long maxDeclaredBytes;
    private final Duration ttl;
    private final Path uploadRoot;
    private final Path contentRoot;
    private final UploadPersistence persistence;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private long declaredBytes;

    public ArtifactUploadService(ArtifactRegistry registry) {
        this(registry, Clock.systemUTC(), DEFAULT_MAX_SESSIONS, DEFAULT_MAX_DECLARED_BYTES, DEFAULT_TTL,
                UploadPersistence.NONE);
    }

    public ArtifactUploadService(ArtifactRegistry registry, Clock clock, int maxSessions,
                                 long maxDeclaredBytes, Duration ttl) {
        this(registry, clock, maxSessions, maxDeclaredBytes, ttl, UploadPersistence.NONE);
    }

    public ArtifactUploadService(ArtifactRegistry registry, Clock clock, int maxSessions,
                                 long maxDeclaredBytes, Duration ttl, UploadPersistence persistence) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        if (maxSessions <= 0 || maxDeclaredBytes <= 0 || ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("upload limits must be positive");
        }
        this.maxSessions = maxSessions;
        this.maxDeclaredBytes = maxDeclaredBytes;
        this.ttl = ttl;
        Path managedRoot = secureDirectory(registry.allowedRoot(), ".veyrion");
        this.uploadRoot = secureDirectory(managedRoot, "uploads");
        this.contentRoot = secureDirectory(secureDirectory(managedRoot, "artifacts"), "sha256");
        restorePersistedSessions();
    }

    public synchronized UploadSession initialize(String projectId, String fileName,
                                                 long sizeBytes, String sha256) {
        cleanupExpired();
        requireStableDirectory(uploadRoot);
        requireProjectId(projectId);
        String extension = extension(fileName);
        String digest = requireDigest(sha256, "sha256");
        if (sizeBytes <= 0 || sizeBytes > registry.maxArtifactBytes()) {
            throw new UploadException(413, "ARTIFACT_TOO_LARGE", "declared artifact size exceeds the limit");
        }
        if (sessions.size() >= maxSessions) {
            throw new UploadException(429, "UPLOAD_SESSION_LIMIT", "upload session limit reached");
        }
        long next;
        try {
            next = Math.addExact(declaredBytes, sizeBytes);
        } catch (ArithmeticException overflow) {
            throw new UploadException(429, "UPLOAD_BYTE_LIMIT", "declared upload byte limit reached");
        }
        if (next > maxDeclaredBytes) {
            throw new UploadException(429, "UPLOAD_BYTE_LIMIT", "declared upload byte limit reached");
        }
        String uploadId = "upload-" + UUID.randomUUID().toString().replace("-", "");
        Path part = uploadRoot.resolve(uploadId + ".part");
        try {
            Files.write(part, new byte[0], StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (IOException failure) {
            throw new UploadException(500, "UPLOAD_STORAGE_ERROR", "upload staging file could not be created");
        }
        Instant now = Instant.now(clock);
        Session session = new Session(uploadId, projectId, fileName, extension, sizeBytes,
                digest, part, now, now.plus(ttl), 0);
        sessions.put(uploadId, session);
        declaredBytes = next;
        try {
            persistence.save(toPersisted(session));
        } catch (RuntimeException failure) {
            sessions.remove(uploadId);
            declaredBytes -= sizeBytes;
            deletePart(part);
            throw persistenceFailure(failure);
        }
        return view(session);
    }

    public synchronized UploadSession append(String projectId, String uploadId, long offset,
                                             long contentLength, String chunkSha256,
                                             InputStream input) throws IOException {
        cleanupExpired();
        requireStableDirectory(uploadRoot);
        Session session = requireSession(projectId, uploadId);
        if (offset != session.offset) {
            throw new UploadException(409, "UPLOAD_OFFSET_MISMATCH", "chunk offset must match the next expected offset");
        }
        if (contentLength <= 0 || contentLength > MAX_CHUNK_BYTES) {
            throw new UploadException(413, "CHUNK_TOO_LARGE", "chunk length must be between 1 byte and 4 MiB");
        }
        if (contentLength > session.sizeBytes - session.offset) {
            throw new UploadException(413, "UPLOAD_SIZE_EXCEEDED", "chunk exceeds the declared artifact size");
        }
        String expectedChunkDigest = requireDigest(chunkSha256, "X-Chunk-SHA256");
        if (Files.isSymbolicLink(session.part)
                || !Files.isRegularFile(session.part, LinkOption.NOFOLLOW_LINKS)
                || Files.size(session.part) != session.offset) {
            throw new UploadException(409, "UPLOAD_STAGING_CHANGED", "upload staging file changed");
        }
        byte[] chunk = input.readNBytes(Math.toIntExact(contentLength) + 1);
        if (chunk.length != contentLength) {
            throw new UploadException(400, "CHUNK_LENGTH_MISMATCH", "chunk body does not match Content-Length");
        }
        String actual = sha256(chunk);
        if (!MessageDigest.isEqual(expectedChunkDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new UploadException(422, "CHUNK_DIGEST_MISMATCH", "chunk SHA-256 does not match");
        }
        long previousOffset = session.offset;
        Files.write(session.part, chunk, StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS);
        session.offset += contentLength;
        try {
            persistence.save(toPersisted(session));
        } catch (RuntimeException failure) {
            session.offset = previousOffset;
            try (var channel = java.nio.channels.FileChannel.open(session.part, StandardOpenOption.WRITE)) {
                channel.truncate(previousOffset);
            } catch (IOException rollbackFailure) {
                throw new UploadException(500, "UPLOAD_STORAGE_ERROR", "upload rollback failed after persistence error");
            }
            throw persistenceFailure(failure);
        }
        return view(session);
    }

    public synchronized ArtifactDescriptor complete(String projectId, String uploadId) throws IOException {
        cleanupExpired();
        requireStableDirectory(uploadRoot);
        requireStableDirectory(contentRoot);
        Session session = requireSession(projectId, uploadId);
        if (session.completed != null) return session.completed;
        if (session.offset != session.sizeBytes || Files.size(session.part) != session.sizeBytes) {
            throw new UploadException(409, "UPLOAD_INCOMPLETE", "uploaded bytes do not match the declared size");
        }
        String actualDigest = ArtifactRegistry.sha256(session.part);
        if (!MessageDigest.isEqual(session.sha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                actualDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new UploadException(422, "ARTIFACT_DIGEST_MISMATCH", "artifact SHA-256 does not match");
        }
        registry.validate(session.part, session.fileName);

        Path prefixRoot = secureDirectory(contentRoot, session.sha256.substring(0, 2));
        Path target = prefixRoot.resolve(session.sha256 + "." + session.extension);
        installAtomically(session.part, target, session.sizeBytes, session.sha256);
        ArtifactDescriptor descriptor = registry.registerManaged(target, session.fileName);
        registry.verifyUnchanged(descriptor);
        session.completed = descriptor;
        return descriptor;
    }

    /** 仅在 project 注册成功后释放 session budget。 */
    public synchronized void finish(String projectId, String uploadId) {
        Session session = requireSession(projectId, uploadId);
        if (session.completed == null) {
            throw new UploadException(409, "UPLOAD_NOT_COMPLETED", "upload has not completed validation");
        }
        try {
            persistence.delete(uploadId);
        } catch (RuntimeException failure) {
            throw persistenceFailure(failure);
        }
        if (sessions.remove(uploadId, session)) declaredBytes -= session.sizeBytes;
    }

    public synchronized void cancel(String projectId, String uploadId) {
        cleanupExpired();
        requireStableDirectory(uploadRoot);
        Session session = requireSession(projectId, uploadId);
        try {
            persistence.delete(uploadId);
        } catch (RuntimeException failure) {
            throw persistenceFailure(failure);
        }
        if (sessions.remove(uploadId, session)) declaredBytes -= session.sizeBytes;
        deletePart(session.part);
    }

    private void installAtomically(Path part, Path target, long sizeBytes, String digest) throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            verifyExisting(target, sizeBytes, digest);
            Files.delete(part);
            return;
        }
        try {
            Files.move(part, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (FileAlreadyExistsException race) {
            verifyExisting(target, sizeBytes, digest);
            Files.deleteIfExists(part);
        } catch (AtomicMoveNotSupportedException unsupported) {
            throw new UploadException(500, "ATOMIC_MOVE_UNAVAILABLE", "managed artifact storage does not support atomic installation");
        }
    }

    private static void verifyExisting(Path target, long sizeBytes, String digest) throws IOException {
        if (Files.isSymbolicLink(target) || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                || Files.size(target) != sizeBytes || !digest.equals(ArtifactRegistry.sha256(target))) {
            throw new UploadException(409, "CONTENT_COLLISION", "managed content path does not match the upload");
        }
    }

    private Session requireSession(String projectId, String uploadId) {
        requireProjectId(projectId);
        if (uploadId == null || !uploadId.matches("upload-[a-f0-9]{32}")) {
            throw new UploadException(404, "UPLOAD_NOT_FOUND", "upload session not found");
        }
        Session session = sessions.get(uploadId);
        if (session == null || !session.projectId.equals(projectId)) {
            throw new UploadException(404, "UPLOAD_NOT_FOUND", "upload session not found");
        }
        return session;
    }

    private void cleanupExpired() {
        Instant now = Instant.now(clock);
        for (Session session : sessions.values()) {
            if (!now.isBefore(session.expiresAt) && sessions.remove(session.uploadId, session)) {
                declaredBytes -= session.sizeBytes;
                try { persistence.delete(session.uploadId); }
                catch (RuntimeException ignored) { /* expired rows are discarded on the next startup */ }
                deletePart(session.part);
            }
        }
    }

    private void restorePersistedSessions() {
        Set<String> restored = new HashSet<>();
        Instant now = Instant.now(clock);
        List<PersistedSession> persisted = persistence.load();
        if (persisted.size() > maxSessions) {
            throw new IllegalStateException("persisted upload session limit exceeded");
        }
        for (PersistedSession item : persisted) {
            try {
                validatePersisted(item, now);
                Path part = uploadRoot.resolve(item.uploadId() + ".part").normalize();
                if (!Files.isRegularFile(part, LinkOption.NOFOLLOW_LINKS)
                        || Files.size(part) != item.nextOffset()) {
                    throw new IllegalArgumentException("staging part does not match persisted offset");
                }
                if (sessions.putIfAbsent(item.uploadId(), new Session(item.uploadId(), item.projectId(),
                        item.fileName(), extension(item.fileName()), item.sizeBytes(), item.sha256(), part,
                        item.createdAt(), item.expiresAt(), item.nextOffset())) != null) {
                    throw new IllegalArgumentException("duplicate persisted upload id");
                }
                restored.add(item.uploadId());
                declaredBytes = Math.addExact(declaredBytes, item.sizeBytes());
            } catch (RuntimeException | IOException invalid) {
                try { persistence.delete(item.uploadId()); } catch (RuntimeException ignored) { }
                deletePart(uploadRoot.resolve(item.uploadId() + ".part").normalize());
            }
        }
        if (declaredBytes > maxDeclaredBytes) {
            throw new IllegalStateException("persisted upload byte limit exceeded");
        }
        cleanupStartupParts(restored);
    }

    private void validatePersisted(PersistedSession item, Instant now) {
        Objects.requireNonNull(item, "persisted upload");
        if (item.uploadId() == null || !item.uploadId().matches("upload-[a-f0-9]{32}")) {
            throw new IllegalArgumentException("invalid persisted upload id");
        }
        requireProjectId(item.projectId());
        extension(item.fileName());
        requireDigest(item.sha256(), "sha256");
        if (item.sizeBytes() <= 0 || item.sizeBytes() > registry.maxArtifactBytes()
                || item.nextOffset() < 0 || item.nextOffset() > item.sizeBytes()
                || item.createdAt() == null || item.expiresAt() == null
                || !item.expiresAt().isAfter(now)) {
            throw new IllegalArgumentException("invalid persisted upload bounds");
        }
        Path part = uploadRoot.resolve(item.uploadId() + ".part").normalize();
        if (!part.getParent().equals(uploadRoot)) throw new IllegalArgumentException("persisted upload escaped staging root");
    }

    private void cleanupStartupParts(Set<String> activeUploadIds) {
        try (var paths = Files.list(uploadRoot)) {
            paths.filter(path -> path.getFileName().toString().matches("upload-[a-f0-9]{32}\\.part"))
                    .filter(path -> !activeUploadIds.contains(path.getFileName().toString().substring(0, 39)))
                    .forEach(this::deletePart);
        } catch (IOException failure) {
            throw new IllegalStateException("cannot clean upload staging directory", failure);
        }
    }

    private PersistedSession toPersisted(Session session) {
        return new PersistedSession(session.uploadId, session.projectId, session.fileName,
                session.sizeBytes, session.sha256, session.offset, session.createdAt, session.expiresAt);
    }

    private static UploadException persistenceFailure(RuntimeException failure) {
        return new UploadException(503, "UPLOAD_PERSISTENCE_ERROR", "upload state could not be persisted");
    }

    private void deletePart(Path part) {
        try {
            if (stableDirectory(uploadRoot) && part.normalize().getParent().equals(uploadRoot)) {
                Files.deleteIfExists(part);
            }
        } catch (IOException ignored) {
            // 清理失败不会给 session 更多 lifetime 或 budget。
        }
    }

    private static void requireStableDirectory(Path directory) {
        if (!stableDirectory(directory)) {
            throw new UploadException(409, "UPLOAD_STORAGE_CHANGED", "managed upload storage changed");
        }
    }

    private static boolean stableDirectory(Path directory) {
        try {
            return !Files.isSymbolicLink(directory)
                    && Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                    && directory.equals(directory.toRealPath());
        } catch (IOException failure) {
            return false;
        }
    }

    private static Path secureDirectory(Path parent, String child) {
        Path candidate = parent.resolve(child).normalize();
        if (!candidate.getParent().equals(parent)) throw new IllegalArgumentException("invalid managed directory");
        try {
            if (Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(candidate) || !Files.isDirectory(candidate, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IllegalStateException("managed path must be a non-symlink directory");
                }
            } else {
                Files.createDirectory(candidate);
            }
            Path real = candidate.toRealPath();
            if (!real.getParent().equals(parent.toRealPath())) {
                throw new IllegalStateException("managed directory escaped the allowed root");
            }
            return real;
        } catch (IOException failure) {
            throw new IllegalStateException("managed directory could not be prepared", failure);
        }
    }

    private static String extension(String fileName) {
        if (fileName == null || fileName.isBlank() || fileName.length() > 255
                || fileName.contains("/") || fileName.contains("\\")
                || fileName.equals(".") || fileName.equals("..")
                || fileName.chars().anyMatch(Character::isISOControl)) {
            throw new UploadException(400, "INVALID_FILE_NAME", "fileName must be a plain file name");
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".jar")) return "jar";
        if (lower.endsWith(".war")) return "war";
        if (lower.endsWith(".class")) return "class";
        throw new UploadException(422, "INVALID_EXTENSION", "fileName must end in .jar, .war or .class");
    }

    private static String requireDigest(String value, String name) {
        if (value == null || !value.matches("[A-Fa-f0-9]{64}")) {
            throw new UploadException(400, "INVALID_DIGEST", name + " must be a 64-character SHA-256");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static void requireProjectId(String projectId) {
        if (projectId == null || !projectId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new UploadException(400, "INVALID_PROJECT", "projectId is invalid");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static UploadSession view(Session session) {
        return new UploadSession(session.uploadId, session.projectId, session.fileName,
                session.sizeBytes, session.sha256, session.offset, session.expiresAt,
                RECOMMENDED_CHUNK_BYTES, MAX_CHUNK_BYTES);
    }

    public record UploadSession(String uploadId, String projectId, String fileName, long sizeBytes,
                                String sha256, long nextOffset, Instant expiresAt,
                                int recommendedChunkBytes, int maxChunkBytes) { }

    public record PersistedSession(String uploadId, String projectId, String fileName, long sizeBytes,
                                   String sha256, long nextOffset, Instant createdAt, Instant expiresAt) { }

    public interface UploadPersistence {
        UploadPersistence NONE = new UploadPersistence() {
            @Override public List<PersistedSession> load() { return List.of(); }
            @Override public void save(PersistedSession session) { }
            @Override public void delete(String uploadId) { }
        };

        List<PersistedSession> load();
        void save(PersistedSession session);
        void delete(String uploadId);
    }

    public static final class UploadException extends RuntimeException {
        private final int status;
        private final String code;

        public UploadException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }

        public int status() { return status; }
        public String code() { return code; }
    }

    private static final class Session {
        private final String uploadId;
        private final String projectId;
        private final String fileName;
        private final String extension;
        private final long sizeBytes;
        private final String sha256;
        private final Path part;
        private final Instant createdAt;
        private final Instant expiresAt;
        private long offset;
        private ArtifactDescriptor completed;

        private Session(String uploadId, String projectId, String fileName, String extension,
                        long sizeBytes, String sha256, Path part, Instant createdAt,
                        Instant expiresAt, long offset) {
            this.uploadId = uploadId;
            this.projectId = projectId;
            this.fileName = fileName;
            this.extension = extension;
            this.sizeBytes = sizeBytes;
            this.sha256 = sha256;
            this.part = part;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.offset = offset;
        }
    }
}
