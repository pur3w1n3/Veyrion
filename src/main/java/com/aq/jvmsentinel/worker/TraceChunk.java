package com.aq.jvmsentinel.worker;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/** 不可变轨迹链元素，其摘要覆盖所有安全相关字段。 */
public record TraceChunk(int schemaVersion, TaskScope scope, long sequence, String previousDigest,
                         Instant emittedAt, byte[] payload, String digest) {
    public TraceChunk {
        WorkerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(scope, "scope");
        if (sequence < 0) throw new IllegalArgumentException("sequence cannot be negative");
        if (sequence == 0) {
            if (previousDigest != null) throw new IllegalArgumentException("first chunk cannot have previousDigest");
        } else {
            previousDigest = WorkerContracts.digest(previousDigest, "previousDigest");
        }
        emittedAt = WorkerContracts.instant(emittedAt, "emittedAt");
        Objects.requireNonNull(payload, "payload");
        if (payload.length > WorkerContracts.MAX_TRACE_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("trace payload exceeds limit");
        }
        payload = payload.clone();
        String calculated = calculateDigest(schemaVersion, scope, sequence, previousDigest, emittedAt, payload);
        if (digest == null) {
            digest = calculated;
        } else {
            WorkerContracts.digest(digest, "digest");
            if (!digest.equals(calculated)) throw new IllegalArgumentException("trace digest does not match content");
        }
    }

    public static TraceChunk create(TaskScope scope, long sequence, String previousDigest,
                                    Instant emittedAt, byte[] payload) {
        return new TraceChunk(WorkerContracts.SCHEMA_VERSION, scope, sequence, previousDigest, emittedAt, payload, null);
    }

    public byte[] payload() {
        return payload.clone();
    }

    public static String calculateDigest(int schemaVersion, TaskScope scope, long sequence,
                                         String previousDigest, Instant emittedAt, byte[] payload) {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(emittedAt, "emittedAt");
        Objects.requireNonNull(payload, "payload");
        ByteArrayOutputStream canonical = new ByteArrayOutputStream();
        canonical.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(schemaVersion).array());
        WorkerContracts.putCanonical(canonical, scope.projectId());
        WorkerContracts.putCanonical(canonical, scope.artifactDigest());
        WorkerContracts.putCanonical(canonical, scope.scanId());
        WorkerContracts.putCanonical(canonical, scope.taskId());
        canonical.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(sequence).array());
        WorkerContracts.putCanonical(canonical, previousDigest == null ? "" : previousDigest);
        canonical.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(emittedAt.getEpochSecond()).array());
        canonical.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(emittedAt.getNano()).array());
        canonical.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(payload.length).array());
        canonical.writeBytes(payload);
        return WorkerContracts.sha256(canonical.toByteArray());
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof TraceChunk chunk
                && schemaVersion == chunk.schemaVersion && sequence == chunk.sequence
                && scope.equals(chunk.scope) && Objects.equals(previousDigest, chunk.previousDigest)
                && emittedAt.equals(chunk.emittedAt) && Arrays.equals(payload, chunk.payload)
                && digest.equals(chunk.digest);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(schemaVersion, scope, sequence, previousDigest, emittedAt, digest)
                + Arrays.hashCode(payload);
    }
}
