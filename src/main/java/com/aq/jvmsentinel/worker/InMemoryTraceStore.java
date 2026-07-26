package com.aq.jvmsentinel.worker;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Bounded, append-only trace store for contract tests and local control-plane use. */
public final class InMemoryTraceStore {
    private static final int MAX_TASKS = 20_000;
    private static final int MAX_CHUNKS_TOTAL = 100_000;
    private static final int MAX_IDEMPOTENCY_KEYS = 100_000;

    private final Clock clock;
    private final TracePersistence persistence;
    private final Map<TaskScope, List<TraceChunk>> traces = new HashMap<>();
    private final Map<ReplayKey, TraceChunk> replays = new LinkedHashMap<>();
    private int chunkCount;

    public InMemoryTraceStore(Clock clock) {
        this(clock, List.of(), (key, chunk) -> { });
    }

    public InMemoryTraceStore(Clock clock, List<StoredTrace> restored, TracePersistence persistence) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        Objects.requireNonNull(restored, "restored");
        for (StoredTrace item : restored) restore(item);
    }

    public synchronized TraceChunk append(String idempotencyKey, TraceChunk chunk) {
        Objects.requireNonNull(chunk, "chunk");
        return append(chunk.scope(), idempotencyKey, chunk);
    }

    public synchronized TraceChunk append(TaskScope scope, String idempotencyKey, TraceChunk chunk) {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(chunk, "chunk");
        String key = WorkerContracts.id(idempotencyKey, "idempotencyKey");
        if (!scope.equals(chunk.scope())) throw new SecurityException("trace scope mismatch");
        ReplayKey replayKey = new ReplayKey(scope, key);
        TraceChunk replay = replays.get(replayKey);
        if (replay != null) {
            if (replay.equals(chunk)) return replay;
            throw new IllegalStateException("idempotency key payload conflict");
        }
        if (replays.size() >= MAX_IDEMPOTENCY_KEYS) throw new IllegalStateException("idempotency key limit reached");
        List<TraceChunk> current = traces.get(scope);
        if (current == null) {
            if (traces.size() >= MAX_TASKS) throw new IllegalStateException("trace task limit reached");
            current = new ArrayList<>();
            traces.put(scope, current);
        }
        if (chunkCount >= MAX_CHUNKS_TOTAL) throw new IllegalStateException("trace chunk limit reached");
        long expectedSequence = current.size();
        String expectedPrevious = current.isEmpty() ? null : current.get(current.size() - 1).digest();
        if (chunk.sequence() != expectedSequence || !Objects.equals(chunk.previousDigest(), expectedPrevious)) {
            throw new IllegalStateException("trace chain is not contiguous");
        }
        // Recompute at the trust boundary in case a future deserializer bypasses the canonical constructor.
        String calculated = TraceChunk.calculateDigest(chunk.schemaVersion(), chunk.scope(), chunk.sequence(),
                chunk.previousDigest(), chunk.emittedAt(), chunk.payload());
        if (!calculated.equals(chunk.digest())) throw new IllegalStateException("trace content was tampered");
        persistence.append(key, chunk);
        current.add(chunk);
        chunkCount++;
        replays.put(replayKey, chunk);
        return chunk;
    }

    public synchronized TraceManifest manifest(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        List<TraceChunk> chunks = traces.getOrDefault(scope, List.of());
        List<TraceManifest.ChunkRef> refs = new ArrayList<>(chunks.size());
        long total = 0;
        for (TraceChunk chunk : chunks) {
            int size = chunk.payload().length;
            total = Math.addExact(total, size);
            refs.add(new TraceManifest.ChunkRef(chunk.sequence(), chunk.digest(), size, chunk.emittedAt()));
        }
        String head = chunks.isEmpty() ? null : chunks.get(chunks.size() - 1).digest();
        return new TraceManifest(WorkerContracts.SCHEMA_VERSION, scope, refs, total, head, clock.instant());
    }

    /**
     * Returns an immutable, payload-copying snapshot for exactly one task scope.
     * Trusted callers must supply both count and byte bounds; oversized traces fail closed.
     */
    public synchronized List<TraceChunk> readChunks(TaskScope scope, int maxChunks, long maxPayloadBytes) {
        Objects.requireNonNull(scope, "scope");
        if (maxChunks <= 0 || maxChunks > 10_000) {
            throw new IllegalArgumentException("maxChunks is outside the read limit");
        }
        if (maxPayloadBytes <= 0) {
            throw new IllegalArgumentException("maxPayloadBytes must be positive");
        }
        List<TraceChunk> current = traces.getOrDefault(scope, List.of());
        if (current.size() > maxChunks) throw new IllegalStateException("trace exceeds chunk read limit");
        long total = 0;
        List<TraceChunk> copy = new ArrayList<>(current.size());
        for (TraceChunk chunk : current) {
            byte[] payload = chunk.payload();
            if (payload.length > maxPayloadBytes - total) {
                throw new IllegalStateException("trace exceeds payload read limit");
            }
            total += payload.length;
            copy.add(new TraceChunk(chunk.schemaVersion(), chunk.scope(), chunk.sequence(),
                    chunk.previousDigest(), chunk.emittedAt(), payload, chunk.digest()));
        }
        return List.copyOf(copy);
    }

    public synchronized void requireCommitted(TaskCheckpoint checkpoint) {
        Objects.requireNonNull(checkpoint, "checkpoint");
        List<TraceChunk> chunks = traces.getOrDefault(checkpoint.scope(), List.of());
        if (checkpoint.traceSequence() == -1) {
            if (!chunks.isEmpty()) throw new IllegalStateException("checkpoint does not reference current trace head");
            return;
        }
        if (checkpoint.traceSequence() != chunks.size() - 1
                || !chunks.get(chunks.size() - 1).digest().equals(checkpoint.traceHeadDigest())) {
            throw new IllegalStateException("checkpoint must reference the committed trace head");
        }
    }

    public synchronized TraceChunk head(TaskScope scope) {
        List<TraceChunk> chunks = traces.get(scope);
        return chunks == null || chunks.isEmpty() ? null : chunks.get(chunks.size() - 1);
    }

    private void restore(StoredTrace item) {
        Objects.requireNonNull(item, "stored trace");
        TraceChunk chunk = item.chunk();
        String key = WorkerContracts.id(item.idempotencyKey(), "idempotencyKey");
        List<TraceChunk> current = traces.computeIfAbsent(chunk.scope(), ignored -> new ArrayList<>());
        if (traces.size() > MAX_TASKS || chunkCount >= MAX_CHUNKS_TOTAL
                || replays.size() >= MAX_IDEMPOTENCY_KEYS) {
            throw new IllegalStateException("restored trace limits exceeded");
        }
        String previous = current.isEmpty() ? null : current.get(current.size() - 1).digest();
        if (chunk.sequence() != current.size() || !Objects.equals(previous, chunk.previousDigest())) {
            throw new IllegalStateException("restored trace chain is not contiguous");
        }
        ReplayKey replayKey = new ReplayKey(chunk.scope(), key);
        if (replays.putIfAbsent(replayKey, chunk) != null) {
            throw new IllegalStateException("duplicate restored trace idempotency key");
        }
        current.add(chunk);
        chunkCount++;
    }

    @FunctionalInterface
    public interface TracePersistence {
        void append(String idempotencyKey, TraceChunk chunk);
    }

    public record StoredTrace(String idempotencyKey, TraceChunk chunk) {
        public StoredTrace {
            WorkerContracts.id(idempotencyKey, "idempotencyKey");
            Objects.requireNonNull(chunk, "chunk");
        }
    }

    private record ReplayKey(TaskScope scope, String key) { }
}
