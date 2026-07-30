package com.aq.jvmsentinel.domain.analyzer;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 原子发布前 staged 的单条 IR/trace 片段。
 * Payload digest 覆盖排序 key=value 行的 canonical UTF-8 以保证确定性。
 */
public record IrChunk(
        int schemaVersion,
        AnalyzerScope scope,
        long sequence,
        String kind,
        String compression,
        String payloadDigest,
        int payloadBytes,
        Map<String, Object> payload
) {
    public static final String KIND_PROGRAM_NODE = "PROGRAM_NODE";
    public static final String KIND_ENTRY = "ENTRY";
    public static final String KIND_COVERAGE_GAP = "COVERAGE_GAP";

    public IrChunk {
        AnalyzerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(scope, "scope");
        if (sequence < 0) {
            throw new IllegalArgumentException("sequence cannot be negative");
        }
        Objects.requireNonNull(kind, "kind");
        if (kind.isBlank()) {
            throw new IllegalArgumentException("kind must not be blank");
        }
        kind = kind.trim();
        compression = compression == null || compression.isBlank() ? "NONE" : compression.trim();
        if (!"NONE".equals(compression) && !"GZIP".equals(compression)) {
            throw new IllegalArgumentException("unsupported compression");
        }
        payload = Map.copyOf(payload == null ? Map.of() : payload);
        String calculated = calculatePayloadDigest(payload);
        if (payloadDigest == null || payloadDigest.isBlank()) {
            payloadDigest = calculated;
        } else {
            AnalyzerContracts.digest(payloadDigest, "payloadDigest");
            if (!payloadDigest.equals(calculated)) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.PAYLOAD_DIGEST_MISMATCH,
                        "payload digest mismatch");
            }
        }
        byte[] raw = canonicalize(payload);
        if (payloadBytes < 0) {
            throw new IllegalArgumentException("payloadBytes cannot be negative");
        }
        if (payloadBytes == 0) {
            payloadBytes = raw.length;
        } else if (payloadBytes != raw.length) {
            throw new IllegalArgumentException("payloadBytes mismatch");
        }
        if (payloadBytes > AnalyzerContracts.MAX_CHUNK_BYTES) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.BUDGET_EXCEEDED,
                    "chunk exceeds maxChunkBytes");
        }
    }

    public static IrChunk create(AnalyzerScope scope, long sequence, String kind,
                                 Map<String, Object> payload) {
        return new IrChunk(AnalyzerContracts.SCHEMA_VERSION, scope, sequence, kind, "NONE",
                null, 0, payload);
    }

    public IrChunkManifest.ChunkRef toRef() {
        return new IrChunkManifest.ChunkRef(sequence, kind, payloadDigest, payloadBytes);
    }

    public static String calculatePayloadDigest(Map<String, Object> payload) {
        return AnalyzerContracts.sha256(canonicalize(payload));
    }

    static byte[] canonicalize(Map<String, Object> payload) {
        StringBuilder builder = new StringBuilder();
        payload.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> builder.append(entry.getKey())
                        .append('=')
                        .append(String.valueOf(entry.getValue()))
                        .append('\n'));
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("scope", scope.toMap());
        map.put("sequence", sequence);
        map.put("kind", kind);
        map.put("compression", compression);
        map.put("payloadDigest", payloadDigest);
        map.put("payloadBytes", payloadBytes);
        map.put("payload", payload);
        return map;
    }
}
