package com.aq.jvmsentinel.worker;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Immutable snapshot of committed trace chunks; it is evidence inventory, not a VERIFIED result. */
public record TraceManifest(int schemaVersion, TaskScope scope, List<ChunkRef> chunks,
                            long totalPayloadBytes, String headDigest, Instant createdAt) {
    private static final int MAX_CHUNKS = 10_000;

    public TraceManifest {
        WorkerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(chunks, "chunks");
        if (chunks.size() > MAX_CHUNKS || chunks.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("chunks exceeds limit or contains null");
        }
        chunks = List.copyOf(chunks);
        if (totalPayloadBytes < 0) throw new IllegalArgumentException("totalPayloadBytes cannot be negative");
        long calculated = chunks.stream().mapToLong(ChunkRef::payloadBytes).sum();
        if (calculated != totalPayloadBytes) throw new IllegalArgumentException("totalPayloadBytes mismatch");
        for (int index = 0; index < chunks.size(); index++) {
            if (chunks.get(index).sequence() != index) throw new IllegalArgumentException("manifest sequence gap");
        }
        if (chunks.isEmpty()) {
            if (headDigest != null) throw new IllegalArgumentException("empty manifest cannot have headDigest");
        } else {
            headDigest = WorkerContracts.digest(headDigest, "headDigest");
            if (!headDigest.equals(chunks.get(chunks.size() - 1).digest())) {
                throw new IllegalArgumentException("headDigest mismatch");
            }
        }
        createdAt = WorkerContracts.instant(createdAt, "createdAt");
    }

    public record ChunkRef(long sequence, String digest, int payloadBytes, Instant emittedAt) {
        public ChunkRef {
            if (sequence < 0) throw new IllegalArgumentException("sequence cannot be negative");
            digest = WorkerContracts.digest(digest, "digest");
            if (payloadBytes < 0 || payloadBytes > WorkerContracts.MAX_TRACE_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("invalid payloadBytes");
            }
            emittedAt = WorkerContracts.instant(emittedAt, "emittedAt");
        }
    }
}
