package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.provider.AgentRole;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Versioned AI job/stage DTOs. Model output is structurally limited to INFERENCE. */
public final class AiContracts {
    public static final int SCHEMA_VERSION = 1;

    private AiContracts() { }

    public record AiJob(int schemaVersion, String workspaceId, String jobId, String artifactDigest,
                        JobStatus status, List<AiStage> stages, Instant createdAt, Instant updatedAt) {
        public AiJob {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            jobId = id(jobId, "jobId");
            artifactDigest = digest(artifactDigest);
            Objects.requireNonNull(status, "status");
            stages = List.copyOf(Objects.requireNonNull(stages, "stages"));
            if (stages.size() > 256) throw new IllegalArgumentException("too many stages");
            for (AiStage stage : stages) {
                if (!workspaceId.equals(stage.workspaceId()) || !jobId.equals(stage.jobId())) {
                    throw new IllegalArgumentException("stage scope mismatch");
                }
            }
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (updatedAt.isBefore(createdAt)) throw new IllegalArgumentException("updatedAt precedes createdAt");
        }
    }

    public record AiStage(int schemaVersion, String workspaceId, String jobId, String stageId,
                          AgentRole role, String modelId, StageStatus status,
                          List<String> inputRefs, InferenceConclusion conclusion,
                          Instant createdAt, Instant updatedAt) {
        public AiStage {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            jobId = id(jobId, "jobId");
            stageId = id(stageId, "stageId");
            Objects.requireNonNull(role, "role");
            modelId = id(modelId, "modelId");
            Objects.requireNonNull(status, "status");
            inputRefs = boundedRefs(inputRefs, "inputRefs");
            if (status == StageStatus.COMPLETED && conclusion == null) {
                throw new IllegalArgumentException("completed stage requires an inference conclusion");
            }
            if (status != StageStatus.COMPLETED && conclusion != null) {
                throw new IllegalArgumentException("only completed stage may carry a conclusion");
            }
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (updatedAt.isBefore(createdAt)) throw new IllegalArgumentException("updatedAt precedes createdAt");
        }
    }

    public record InferenceConclusion(String summary, double confidence,
                                      List<String> evidenceRefs) {
        public InferenceConclusion {
            summary = text(summary, "summary", 16_384);
            if (!Double.isFinite(confidence) || confidence < 0.0 || confidence > 1.0) {
                throw new IllegalArgumentException("confidence must be between zero and one");
            }
            evidenceRefs = boundedRefs(evidenceRefs, "evidenceRefs");
        }

        /** Deliberately has no VERIFIED option. */
        public ConclusionKind classification() { return ConclusionKind.INFERENCE; }
    }

    public enum ConclusionKind {
        INFERENCE
    }

    public enum JobStatus {
        QUEUED,
        RUNNING,
        COMPLETED,
        FAILED,
        CANCELLED,
        BLOCKED
    }

    public enum StageStatus {
        QUEUED,
        RUNNING,
        COMPLETED,
        FAILED,
        CANCELLED,
        BLOCKED,
        SKIPPED
    }

    private static List<String> boundedRefs(List<String> values, String name) {
        Objects.requireNonNull(values, name);
        if (values.size() > 4096) throw new IllegalArgumentException(name + " is too large");
        return values.stream().map(value -> id(value, name)).toList();
    }

    private static void version(int value) {
        if (value != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
    }

    private static String digest(String value) {
        value = id(value, "artifactDigest");
        if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("artifactDigest must be SHA-256");
        return value;
    }

    private static String id(String value, String name) {
        return text(value, name, 512);
    }

    private static String text(String value, String name, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(c -> c == 0 || c == '\r')) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }
}
