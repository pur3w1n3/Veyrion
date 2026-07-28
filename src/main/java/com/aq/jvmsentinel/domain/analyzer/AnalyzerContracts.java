package com.aq.jvmsentinel.domain.analyzer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/** Shared validation helpers for the out-of-process Analyzer protocol (P1-07). */
final class AnalyzerContracts {
    static final int SCHEMA_VERSION = 1;
    static final int MAX_CHUNKS = 256;
    static final int MAX_CHUNK_BYTES = 256 * 1024;
    static final int MAX_TOTAL_BYTES = 1024 * 1024;
    static final int MAX_COLLECTION = 128;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    private AnalyzerContracts() {
    }

    /** Wire types accept any positive version; {@link AnalyzerIngress} enforces session range. */
    static void schemaVersion(int value) {
        if (value < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
    }

    static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!ID.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
        return value;
    }

    static String digest(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!SHA256.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be a lowercase SHA-256");
        }
        return value;
    }

    static <T> List<T> boundedCopy(List<T> values, String name, int max) {
        Objects.requireNonNull(values, name);
        if (values.size() > max) {
            throw new IllegalArgumentException(name + " exceeds limit");
        }
        if (values.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException(name + " contains null");
        }
        return List.copyOf(values);
    }

    static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    static String sha256Utf8(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    static void putCanonical(java.io.ByteArrayOutputStream output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        output.writeBytes(bytes);
    }
}
