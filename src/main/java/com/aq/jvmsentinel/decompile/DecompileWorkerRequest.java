package com.aq.jvmsentinel.decompile;

import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.util.Objects;

/**
 * 独立低权限 Worker 请求。仅描述性，不能在 Control Plane 进程内执行 decompiler。
 */
public record DecompileWorkerRequest(
        int schemaVersion,
        String projectId,
        String scanId,
        String taskId,
        String artifactDigest,
        String readOnlyArtifactPath,
        boolean inputReadOnly,
        NetworkPolicy networkPolicy,
        WorkerCapability requiredCapability,
        DecompileBudget budget,
        DecompilerToolArtifact primaryTool,
        DecompilerToolArtifact validationTool) {
    public static final int SCHEMA_VERSION = 1;
    public static final String ARTIFACT_PATH = "/input/original.jar";

    public DecompileWorkerRequest {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        projectId = id(projectId, "projectId");
        scanId = id(scanId, "scanId");
        taskId = id(taskId, "taskId");
        artifactDigest = digest(artifactDigest, "artifactDigest");
        if (!ARTIFACT_PATH.equals(readOnlyArtifactPath) || !inputReadOnly) {
            throw new IllegalArgumentException("decompiler input must be the fixed read-only artifact mount");
        }
        Objects.requireNonNull(networkPolicy, "networkPolicy");
        if (!networkPolicy.equals(NetworkPolicy.denyAll())) {
            throw new IllegalArgumentException("decompilation must run without network access");
        }
        if (requiredCapability != WorkerCapability.HARDENED_GVISOR
                && requiredCapability != WorkerCapability.HARDENED_KATA) {
            throw new IllegalArgumentException("decompilation requires a hardened isolated Worker");
        }
        Objects.requireNonNull(budget, "budget");
        Objects.requireNonNull(primaryTool, "primaryTool");
        Objects.requireNonNull(validationTool, "validationTool");
        if (primaryTool.tool() != DecompilerTool.VINEFLOWER
                || validationTool.tool() != DecompilerTool.CFR) {
            throw new IllegalArgumentException("tool policy requires Vineflower primary and CFR validation");
        }
        if (primaryTool.sha256().equals(validationTool.sha256())) {
            throw new IllegalArgumentException("tool artifacts must have distinct pinned digests");
        }
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
        return value;
    }

    static String digest(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException(name + " must be SHA-256");
        return value;
    }
}
