package com.aq.jvmsentinel.decompile;

import java.util.List;
import java.util.Objects;

/**
 * Worker executor 的固定 argv 模板。不接受 shell 字符串或调用方提供的 option，
 * Worker 使用前必须校验 tool digest。
 */
public final class DecompileCommandTemplate {
    public static final String JAVA = "/opt/java/bin/java";
    public static final String PRIMARY_OUTPUT = "/output/vineflower";
    public static final String VALIDATION_OUTPUT = "/output/cfr";

    private DecompileCommandTemplate() { }

    public static List<String> arguments(DecompileWorkerRequest request, DecompilerTool tool,
                                         String verifiedToolDigest) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(tool, "tool");
        DecompilerToolArtifact artifact = tool == DecompilerTool.VINEFLOWER
                ? request.primaryTool() : request.validationTool();
        if (!artifact.sha256().equals(DecompileWorkerRequest.digest(verifiedToolDigest, "verifiedToolDigest"))) {
            throw new SecurityException("decompiler tool digest mismatch");
        }
        if (tool == DecompilerTool.VINEFLOWER) {
            return List.of(JAVA, "-cp", artifact.sandboxJarPath(), artifact.tool().mainClass(),
                    "-dgs=1", "-rsy=1", request.readOnlyArtifactPath(), PRIMARY_OUTPUT);
        }
        return List.of(JAVA, "-cp", artifact.sandboxJarPath(), artifact.tool().mainClass(),
                request.readOnlyArtifactPath(), "--outputdir", VALIDATION_OUTPUT, "--silent", "true");
    }
}
