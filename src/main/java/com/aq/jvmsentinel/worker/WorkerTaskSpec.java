package com.aq.jvmsentinel.worker;

import java.util.Objects;

/** Versioned task contract. It expresses a requirement; it never mutates host permissions. */
public record WorkerTaskSpec(int schemaVersion, String projectId, String artifactDigest, String scanId,
                             String taskId, String targetEntryId, boolean authorized, boolean fixtureOnly,
                             ResourceBudget resourceBudget, NetworkPolicy networkPolicy,
                             WorkerCapability requiredCapability, String fixtureId, String imageUri,
                             String mainClass, String fixtureDigest) {
    /** Preserves the original contract constructor for existing internal callers. */
    public WorkerTaskSpec(int schemaVersion, String projectId, String artifactDigest, String scanId,
                          String taskId, String targetEntryId, boolean authorized, boolean fixtureOnly,
                          ResourceBudget resourceBudget, NetworkPolicy networkPolicy,
                          WorkerCapability requiredCapability) {
        this(schemaVersion, projectId, artifactDigest, scanId, taskId, targetEntryId, authorized,
                fixtureOnly, resourceBudget, networkPolicy, requiredCapability, null, null, null, null);
    }

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
        int fixtureFieldCount = (fixtureId == null ? 0 : 1) + (imageUri == null ? 0 : 1)
                + (mainClass == null ? 0 : 1) + (fixtureDigest == null ? 0 : 1);
        if (fixtureFieldCount != 0 && fixtureFieldCount != 4) {
            throw new IllegalArgumentException("fixture runtime fields must be supplied together");
        }
        if (fixtureFieldCount == 4) {
            fixtureId = WorkerContracts.id(fixtureId, "fixtureId");
            if (imageUri.length() > 512
                    || !imageUri.matches("[a-z0-9.-]+(?:/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}")
                    || !imageUri.endsWith("@sha256:" + fixtureDigest)) {
                throw new IllegalArgumentException("imageUri is invalid");
            }
            if (!mainClass.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,254}")) {
                throw new IllegalArgumentException("mainClass is invalid");
            }
            fixtureDigest = WorkerContracts.digest(fixtureDigest, "fixtureDigest");
            if (!fixtureOnly || requiredCapability != WorkerCapability.FIXTURE_RUNC) {
                throw new IllegalArgumentException("fixture runtime fields require FIXTURE_RUNC");
            }
        }
    }

    public TaskScope scope() {
        return TaskScope.of(this);
    }
}
