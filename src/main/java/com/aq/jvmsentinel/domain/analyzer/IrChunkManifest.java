package com.aq.jvmsentinel.domain.analyzer;

import java.util.List;
import java.util.Objects;

/** Ordered inventory of staged IR chunks; incomplete manifests never publish. */
public record IrChunkManifest(
        List<ChunkRef> chunks,
        long totalPayloadBytes,
        String headDigest
) {
    public IrChunkManifest {
        chunks = AnalyzerContracts.boundedCopy(chunks, "chunks", AnalyzerContracts.MAX_CHUNKS);
        if (totalPayloadBytes < 0) {
            throw new IllegalArgumentException("totalPayloadBytes cannot be negative");
        }
        long calculated = chunks.stream().mapToLong(ChunkRef::payloadBytes).sum();
        if (calculated != totalPayloadBytes) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                    "totalPayloadBytes mismatch");
        }
        for (int index = 0; index < chunks.size(); index++) {
            if (chunks.get(index).sequence() != index) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                        "manifest sequence gap at " + index);
            }
        }
        if (chunks.isEmpty()) {
            if (headDigest != null) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                        "empty manifest cannot have headDigest");
            }
        } else {
            headDigest = AnalyzerContracts.digest(headDigest, "headDigest");
            if (!headDigest.equals(chunks.get(chunks.size() - 1).payloadDigest())) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                        "headDigest mismatch");
            }
        }
    }

    public static IrChunkManifest of(List<IrChunk> staged) {
        Objects.requireNonNull(staged, "staged");
        List<ChunkRef> refs = staged.stream().map(IrChunk::toRef).toList();
        long total = refs.stream().mapToLong(ChunkRef::payloadBytes).sum();
        String head = refs.isEmpty() ? null : refs.get(refs.size() - 1).payloadDigest();
        return new IrChunkManifest(refs, total, head);
    }

    public record ChunkRef(long sequence, String kind, String payloadDigest, int payloadBytes) {
        public ChunkRef {
            if (sequence < 0) {
                throw new IllegalArgumentException("sequence cannot be negative");
            }
            Objects.requireNonNull(kind, "kind");
            if (kind.isBlank()) {
                throw new IllegalArgumentException("kind must not be blank");
            }
            payloadDigest = AnalyzerContracts.digest(payloadDigest, "payloadDigest");
            if (payloadBytes < 0 || payloadBytes > AnalyzerContracts.MAX_CHUNK_BYTES) {
                throw new IllegalArgumentException("invalid payloadBytes");
            }
        }
    }
}
