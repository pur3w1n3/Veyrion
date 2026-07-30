package com.aq.jvmsentinel.worker;

/** 不可变的 project/artifact/scan/task 授权范围。 */
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
