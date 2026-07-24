package com.aq.jvmsentinel.decompile;

import java.util.List;
import java.util.Objects;

/**
 * Fixed argv templates for a Worker executor. No shell string or caller-supplied option is
 * accepted, and the tool digest must be verified by the Worker before using these arguments.
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
