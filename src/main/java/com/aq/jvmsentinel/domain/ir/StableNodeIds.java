package com.aq.jvmsentinel.domain.ir;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;

/**
 * 稳定 Evidence Graph node ID 策略（P1-02）。
 *
 * <p>IDs are deterministic within a scan and have the form {@code {type}:{key}}.
 * 刻意省略 project/scan 前缀 — 那些位于 {@link EvidenceGraph}。
 * Key 在存在时复用 legacy DTO identity，以便 finding 可解析
 * {@code entrypointId}/{@code sinkId}/evidence refs without rewriting old wire fields.
 *
 * <ul>
 *   <li>{@code program:class:{binaryName}}</li>
 *   <li>{@code program:method:{owner}#{name}{descriptor}}</li>
 *   <li>{@code program:field:{owner}#{name}:{descriptor}}</li>
 *   <li>{@code entry:{entryDtoId}} — HTTP/RPC/message surfaces (not AUTH filter rows)</li>
 *   <li>{@code trust:{entryId}:{param}}</li>
 *   <li>{@code effect:{sinkDtoId}}</li>
 *   <li>{@code guard:{key}} — ROLE/TENANT precondition, AUTH entry, or AUTH_GAP finding sinkId</li>
 *   <li>{@code sanitizer:{key}}</li>
 *   <li>{@code state:{entryId}:{stateKey}}</li>
 *   <li>{@code resource:{dependencyId}}</li>
 *   <li>{@code runtime:{pathRunId}}</li>
 * </ul>
 *
 * <p>Unknown producers must not invent colliding prefixes; namespaced extensions go under
 * 说明：node {@code extensions} 永不进入 ID namespace。
 */
public final class StableNodeIds {
    private StableNodeIds() {
    }

    public static String programClass(String binaryName) {
        return "program:class:" + normalize(binaryName);
    }

    public static String programMethod(String owner, String name, String descriptor) {
        return "program:method:" + normalize(owner) + "#" + normalize(name) + nullToEmpty(descriptor);
    }

    public static String programField(String owner, String name, String descriptor) {
        return "program:field:" + normalize(owner) + "#" + normalize(name) + ":" + nullToEmpty(descriptor);
    }

    public static String entry(String entryId) {
        return "entry:" + requireKey(entryId, "entryId");
    }

    public static String trust(String entryId, String param) {
        return "trust:" + requireKey(entryId, "entryId") + ":" + normalize(param);
    }

    public static String effect(String sinkId) {
        return "effect:" + requireKey(sinkId, "sinkId");
    }

    public static String guard(String key) {
        String trimmed = requireKey(key, "guardKey");
        if (trimmed.startsWith("guard:")) {
            return trimmed;
        }
        return "guard:" + trimmed;
    }

    public static String sanitizer(String key) {
        return "sanitizer:" + requireKey(key, "sanitizerKey");
    }

    public static String state(String entryId, String stateKey) {
        return "state:" + requireKey(entryId, "entryId") + ":" + normalize(stateKey);
    }

    public static String resource(String dependencyId) {
        return "resource:" + requireKey(dependencyId, "dependencyId");
    }

    public static String runtime(String pathRunId) {
        return "runtime:" + requireKey(pathRunId, "pathRunId");
    }

    public static String edge(EdgeKind kind, String fromId, String toId) {
        Objects.requireNonNull(kind, "kind");
        return "edge:" + kind.name().toLowerCase(Locale.ROOT) + ":"
                + requireKey(fromId, "fromId") + "->" + requireKey(toId, "toId");
    }

    /** Compact fingerprint when a free-form label must become a key fragment. */
    public static String fingerprint(String raw) {
        String text = raw == null ? "" : raw.trim();
        if (text.isEmpty()) return "empty";
        if (text.length() <= 64 && text.chars().allMatch(ch ->
                (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                        || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ':'
                        || ch == '/' || ch == '#')) {
            return text;
        }
        int hash = 0;
        for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
            hash = 31 * hash + (b & 0xff);
        }
        return "h" + Integer.toHexString(hash);
    }

    private static String requireKey(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "_" : value.trim().replace(' ', '_');
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
