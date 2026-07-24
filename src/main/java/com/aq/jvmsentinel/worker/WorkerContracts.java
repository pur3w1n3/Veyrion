package com.aq.jvmsentinel.worker;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

final class WorkerContracts {
    static final int SCHEMA_VERSION = 1;
    static final int MAX_COLLECTION_SIZE = 128;
    static final int MAX_TRACE_PAYLOAD_BYTES = 1024 * 1024;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    private WorkerContracts() { }

    static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!ID.matcher(value).matches()) throw new IllegalArgumentException(name + " contains invalid characters");
        return value;
    }

    static String digest(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!SHA256.matcher(value).matches()) throw new IllegalArgumentException(name + " must be a lowercase SHA-256");
        return value;
    }

    static Instant instant(Instant value, String name) {
        return Objects.requireNonNull(value, name);
    }

    static void schemaVersion(int value) {
        if (value != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
    }

    static long positive(long value, String name) {
        if (value <= 0) throw new IllegalArgumentException(name + " must be positive");
        return value;
    }

    static <T> List<T> boundedCopy(List<T> values, String name) {
        Objects.requireNonNull(values, name);
        if (values.size() > MAX_COLLECTION_SIZE) throw new IllegalArgumentException(name + " exceeds limit");
        if (values.stream().anyMatch(Objects::isNull)) throw new IllegalArgumentException(name + " contains null");
        return List.copyOf(values);
    }

    static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    static void putCanonical(java.io.ByteArrayOutputStream output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeBytes(java.nio.ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        output.writeBytes(bytes);
    }
}
