package com.aq.jvmsentinel.worker;

/** Immutable project/artifact/scan/task authorization scope. */
public record TaskScope(String projectId, String artifactDigest, String scanId, String taskId) {
    public TaskScope {
        projectId = WorkerContracts.id(projectId, "projectId");
        artifactDigest = WorkerContracts.digest(artifactDigest, "artifactDigest");
        scanId = WorkerContracts.id(scanId, "scanId");
        taskId = WorkerContracts.id(taskId, "taskId");
    }

    public static TaskScope of(WorkerTaskSpec spec) {
        return new TaskScope(spec.projectId(), spec.artifactDigest(), spec.scanId(), spec.taskId());
    }
}
