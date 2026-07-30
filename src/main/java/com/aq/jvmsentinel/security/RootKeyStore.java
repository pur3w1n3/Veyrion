package com.aq.jvmsentinel.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** 文件 backed root key store。root key 字节永不经过 repository/database API。 */
public final class RootKeyStore {
    private static final int KEY_BYTES = 32;
    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<AclEntryPermission> WINDOWS_PERMISSIONS = Set.copyOf(EnumSet.of(
            AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
            AclEntryPermission.APPEND_DATA, AclEntryPermission.READ_NAMED_ATTRS,
            AclEntryPermission.WRITE_NAMED_ATTRS, AclEntryPermission.READ_ATTRIBUTES,
            AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.READ_ACL,
            AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER,
            AclEntryPermission.SYNCHRONIZE,
            AclEntryPermission.DELETE));

    private final Path keyPath;
    private final SecureRandom random;

    public RootKeyStore(Path keyPath) {
        this(keyPath, new SecureRandom());
    }

    public RootKeyStore(Path keyPath, SecureRandom random) {
        this.keyPath = Objects.requireNonNull(keyPath, "keyPath").toAbsolutePath().normalize();
        this.random = Objects.requireNonNull(random, "random");
        if (this.keyPath.getParent() == null) throw new IllegalArgumentException("keyPath must have a parent");
    }

    public LoadedRootKey loadOrCreate(DeploymentPolicy policy) throws IOException {
        Objects.requireNonNull(policy, "policy");
        Files.createDirectories(keyPath.getParent());
        rejectLinks();
        boolean created = false;
        if (!Files.exists(keyPath, LinkOption.NOFOLLOW_LINKS)) {
            created = createAtomically();
        }
        rejectLinks();
        PermissionStatus status = secureAndVerify(keyPath);
        if (policy.requiresConfirmedPermissions() && status != PermissionStatus.CONFIRMED_OWNER_ONLY) {
            if (created) Files.deleteIfExists(keyPath);
            throw new SecurityException("root key permissions cannot be confirmed for this deployment");
        }
        byte[] keyBytes = Files.readAllBytes(keyPath);
        try {
            if (keyBytes.length != KEY_BYTES) throw new SecurityException("root key file must contain exactly 256 bits");
            return new LoadedRootKey(new SecretKeySpec(keyBytes, "AES"), status, created);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private boolean createAtomically() throws IOException {
        Path parent = keyPath.getParent();
        FileAttribute<?>[] attributes = Files.getFileStore(parent).supportsFileAttributeView("posix")
                ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(OWNER_ONLY)}
                : new FileAttribute<?>[0];
        Path temporary = Files.createTempFile(parent, ".veyrion-root-key-", ".tmp", attributes);
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(keyBytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            secureAndVerify(temporary);
            try {
                Files.move(temporary, keyPath, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                return true;
            } catch (java.nio.file.FileAlreadyExistsException race) {
                return false;
            } catch (AtomicMoveNotSupportedException unsupported) {
                throw new IOException("filesystem does not support atomic root key creation", unsupported);
            }
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Files.deleteIfExists(temporary);
        }
    }

    private void rejectLinks() throws IOException {
        if (Files.isSymbolicLink(keyPath) || Files.isSymbolicLink(keyPath.getParent())) {
            throw new SecurityException("root key path cannot be a symbolic link");
        }
        if (Files.exists(keyPath, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(keyPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("root key path must be a regular file");
        }
    }

    private static PermissionStatus secureAndVerify(Path path) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
            return Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(OWNER_ONLY)
                    ? PermissionStatus.CONFIRMED_OWNER_ONLY : PermissionStatus.UNCONFIRMED;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) return PermissionStatus.UNSUPPORTED;
        try {
            UserPrincipal current = currentUser(path);
            AclEntry ownerEntry = AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(current)
                    .setPermissions(WINDOWS_PERMISSIONS)
                    .setFlags(EnumSet.noneOf(AclEntryFlag.class))
                    .build();
            acl.setOwner(current);
            acl.setAcl(List.of(ownerEntry));
            List<AclEntry> actual = acl.getAcl();
            boolean confirmed = acl.getOwner().equals(current) && actual.size() == 1
                    && actual.get(0).type() == AclEntryType.ALLOW
                    && actual.get(0).principal().equals(current)
                    && actual.get(0).permissions().containsAll(WINDOWS_PERMISSIONS);
            return confirmed ? PermissionStatus.CONFIRMED_OWNER_ONLY : PermissionStatus.UNCONFIRMED;
        } catch (IOException | UnsupportedOperationException | SecurityException failure) {
            return PermissionStatus.UNCONFIRMED;
        }
    }

    private static UserPrincipal currentUser(Path path) throws IOException {
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        String currentName = System.getProperty("user.name");
        if (currentName == null || currentName.isBlank()) return owner;
        UserPrincipalLookupService lookup = path.getFileSystem().getUserPrincipalLookupService();
        try {
            return lookup.lookupPrincipalByName(currentName);
        } catch (java.nio.file.attribute.UserPrincipalNotFoundException notFound) {
            return owner;
        }
    }

    public record DeploymentPolicy(boolean loopbackOnly, boolean production) {
        public boolean requiresConfirmedPermissions() {
            return production || !loopbackOnly;
        }
    }

    public enum PermissionStatus {
        CONFIRMED_OWNER_ONLY,
        UNCONFIRMED,
        UNSUPPORTED
    }

    public record LoadedRootKey(SecretKey key, PermissionStatus permissionStatus, boolean created) {
        public LoadedRootKey {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(permissionStatus, "permissionStatus");
        }
    }
}
