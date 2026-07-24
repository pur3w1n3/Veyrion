package com.aq.jvmsentinel.worker;

import java.util.Objects;

/** Versioned task contract. It expresses a requirement; it never mutates host permissions. */
public record WorkerTaskSpec(int schemaVersion, String projectId, String artifactDigest, String scanId,
                             String taskId, String targetEntryId, boolean authorized, boolean fixtureOnly,
                             ResourceBudget resourceBudget, NetworkPolicy networkPolicy,
                             WorkerCapability requiredCapability) {
    public WorkerTaskSpec {
        WorkerContracts.schemaVersion(schemaVersion);
        projectId = WorkerContracts.id(projectId, "projectId");
        artifactDigest = WorkerContracts.digest(artifactDigest, "artifactDigest");
        scanId = WorkerContracts.id(scanId, "scanId");
        taskId = WorkerContracts.id(taskId, "taskId");
        targetEntryId = WorkerContracts.id(targetEntryId, "targetEntryId");
        Objects.requireNonNull(resourceBudget, "resourceBudget");
        Objects.requireNonNull(networkPolicy, "networkPolicy");
        Objects.requireNonNull(requiredCapability, "requiredCapability");
        if (requiredCapability == WorkerCapability.FIXTURE_RUNC && !fixtureOnly) {
            throw new IllegalArgumentException("FIXTURE_RUNC is restricted to trusted fixtures");
        }
        if (requiredCapability == WorkerCapability.STATIC_ONLY && networkPolicy.mode()
                != com.aq.jvmsentinel.policy.NetworkMode.DENY) {
            throw new IllegalArgumentException("STATIC_ONLY tasks cannot request network access");
        }
    }

    public TaskScope scope() {
        return TaskScope.of(this);
    }
}
