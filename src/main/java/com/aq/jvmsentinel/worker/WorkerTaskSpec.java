package com.aq.jvmsentinel.worker;

import java.util.Objects;

/** 版本化任务合同。表达需求；永不改变宿主权限。 */
public record WorkerTaskSpec(int schemaVersion, String projectId, String artifactDigest, String scanId,
                             String taskId, String targetEntryId, boolean authorized,
                             ResourceBudget resourceBudget, NetworkPolicy networkPolicy,
                             WorkerCapability requiredCapability) {
    /**
     * v1 源码兼容。已移除的 fixture 判别器仅可为 false。
     */
    public WorkerTaskSpec(int schemaVersion, String projectId, String artifactDigest, String scanId,
                          String taskId, String targetEntryId, boolean authorized, boolean fixtureOnly,
                          ResourceBudget resourceBudget, NetworkPolicy networkPolicy,
                          WorkerCapability requiredCapability) {
        this(schemaVersion, projectId, artifactDigest, scanId, taskId, targetEntryId, authorized,
                rejectFixture(fixtureOnly, resourceBudget), networkPolicy, requiredCapability);
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
        if (requiredCapability != WorkerCapability.STATIC_ONLY && !authorized) {
            throw new IllegalArgumentException("dynamic artifact execution requires explicit authorization");
        }
        if (requiredCapability == WorkerCapability.TRUSTED_DOCKER) {
            if (networkPolicy.mode() != com.aq.jvmsentinel.policy.NetworkMode.DENY
                    || !networkPolicy.allowlist().isEmpty()) {
                throw new IllegalArgumentException("TRUSTED_DOCKER requires deny-all network policy");
            }
        }
        if (requiredCapability == WorkerCapability.STATIC_ONLY && networkPolicy.mode()
                != com.aq.jvmsentinel.policy.NetworkMode.DENY) {
            throw new IllegalArgumentException("STATIC_ONLY tasks cannot request network access");
        }
    }

    public TaskScope scope() {
        return TaskScope.of(this);
    }

    private static ResourceBudget rejectFixture(boolean fixtureOnly, ResourceBudget budget) {
        if (fixtureOnly) throw new IllegalArgumentException("controlled fixture tasks are no longer supported");
        return budget;
    }
}
