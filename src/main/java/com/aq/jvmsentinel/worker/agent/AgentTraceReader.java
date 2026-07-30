package com.aq.jvmsentinel.worker.agent;

import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.worker.ExternalArtifactPaths;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.ResourceBudget;

import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;

/**
 * 通过有界 Base64 块从沙箱读取 agent / 探针 JSONL 轨迹。
 */
public final class AgentTraceReader {
    private AgentTraceReader() { }

    public static long agentTraceBudget(ResourceBudget budget, int probeCount) {
        Objects.requireNonNull(budget, "budget");
        long total = Math.min(ExternalArtifactPaths.MAX_TRACE_BYTES, budget.maxTraceBytes());
        int probes = Math.max(1, Math.min(ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES, probeCount));
        long desiredReserve = ExternalArtifactPaths.MIN_PROBE_TRACE_RESERVE_BYTES
                + probes * ExternalArtifactPaths.PROBE_TRACE_BYTES_PER_ENTRY;
        long reserve = Math.min(desiredReserve, Math.max(0L, total - 256L));
        return total - reserve;
    }

    /**
     * 仅通过固定轨迹路径的有界 Base64 块读取。保留沙箱时 live Agent 仍可能追加，
     * 故先复制到稳定的 {@code *.snapshot}，再按冻结大小校验每个块。
     */
    public static byte[] readTraceFile(SandboxRuntimeClient sandbox, String sandboxId, String path,
                                       long maxBytes, boolean required) {
        Objects.requireNonNull(sandbox, "sandbox");
        if (!ExternalArtifactPaths.TRACE_FILE.equals(path)
                && !ExternalArtifactPaths.PROBE_TRACE_FILE.equals(path)) {
            throw new SecurityException("trace read path is not allowlisted");
        }
        if (maxBytes < 0 || maxBytes > ExternalArtifactPaths.MAX_TRACE_BYTES) {
            throw new SecurityException("trace read budget is outside limits");
        }
        String snapshot = path + ".snapshot";
        try {
            // 先冻结 JSONL 再 sizing/读取：保留应用经 FileChannel 持续写入。
            String sizeCommand = required
                    ? "cp -f " + path + " " + snapshot + " && wc -c < " + snapshot
                    : "if [ -f " + path + " ]; then cp -f " + path + " " + snapshot
                            + " && wc -c < " + snapshot + "; else printf '0\\n'; fi";
            CommandResult sizeResult = sandbox.command(sandboxId, new CommandRequest(
                    sizeCommand, ExternalArtifactPaths.WORKING_DIRECTORY, Duration.ofSeconds(20),
                    ExternalArtifactPaths.SANDBOX_UID, ExternalArtifactPaths.SANDBOX_GID));
            String sizeText = sizeResult.stdout().strip();
            if (sizeResult.exitCode() != 0 || !sizeText.matches("[0-9]{1,10}")) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_READ_FAILED", "trace size could not be read", null);
            }
            long size = Long.parseLong(sizeText);
            if (size == 0) {
                if (required) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED", "required Agent trace is empty", null);
                }
                return new byte[0];
            }
            if (size > maxBytes) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_TOO_LARGE", "Agent and probe trace exceed the task budget", null);
            }

            ByteArrayOutputStream output = new ByteArrayOutputStream(Math.toIntExact(size));
            int blocks = Math.toIntExact((size + ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES - 1)
                    / ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES);
            for (int block = 0; block < blocks; block++) {
                String command = "dd if=" + snapshot + " bs=" + ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES
                        + " skip=" + block + " count=1 2>/dev/null"
                        + " | base64 | tr -d '\\r\\n'";
                CommandResult chunk = sandbox.command(sandboxId, new CommandRequest(
                        command, ExternalArtifactPaths.WORKING_DIRECTORY, Duration.ofSeconds(15),
                        ExternalArtifactPaths.SANDBOX_UID, ExternalArtifactPaths.SANDBOX_GID));
                if (chunk.exitCode() != 0) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED", "trace block command failed", null);
                }
                String encoded = chunk.stdout() == null ? "" : chunk.stdout().replaceAll("\\s+", "");
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException malformed) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED", "trace block is not valid Base64", malformed);
                }
                int expected = (int) Math.min(ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES,
                        size - (long) block * ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES);
                if (decoded.length != expected) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED",
                            "trace block length mismatch (block=" + block
                                    + " expected=" + expected
                                    + " actual=" + decoded.length + ")",
                            null);
                }
                output.write(decoded, 0, decoded.length);
            }
            byte[] result = output.toByteArray();
            if (result.length != size) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_READ_FAILED", "trace length changed during read", null);
            }
            return result;
        } catch (ExternalArtifactTaskExecutor.ExternalArtifactExecutionException failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "TRACE_READ_FAILED", "trace could not be read safely", failure);
        } finally {
            try {
                sandbox.command(sandboxId, new CommandRequest(
                        "rm -f " + snapshot,
                        ExternalArtifactPaths.WORKING_DIRECTORY, Duration.ofSeconds(5),
                        ExternalArtifactPaths.SANDBOX_UID, ExternalArtifactPaths.SANDBOX_GID));
            } catch (RuntimeException ignored) {
                // 尽力清理 trace tmpfs 上的 snapshot。
            }
        }
    }
}
