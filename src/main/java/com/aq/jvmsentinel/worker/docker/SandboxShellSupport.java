package com.aq.jvmsentinel.worker.docker;

import com.aq.jvmsentinel.worker.ExternalArtifactPaths;

/**
 * 容器内 shell 进度写入与引号转义。
 */
public final class SandboxShellSupport {
    private SandboxShellSupport() { }

    public static String writeProgress(String message) {
        return "printf '%s\\n' " + shellSingleQuoted(message) + " > "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/progress.txt";
    }

    public static String shellSingleQuoted(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
