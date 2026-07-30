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
    /** 必需轨迹尚未落盘时的有界等待（保留沙箱下 Agent 仍可能刚打开文件）。 */
    private static final int MISSING_TRACE_ATTEMPTS = 8;
    private static final long MISSING_TRACE_BACKOFF_MILLIS = 250L;

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
     * 仅通过固定轨迹路径的有界 Base64 块读取。
     *
     * <p>保留沙箱时 live Agent 仍可能追加写入。不得整文件 {@code cp} 到 snapshot：
     * 轨迹预算可接近 tmpfs 上限（maxTrace+headroom），再复制一份会 ENOSPC，被误报为
     * {@code trace size could not be read}。改为冻结字节长度后按前缀分块读取，
     * 每块经 {@code head -c} 截断，避免追加导致块长度漂移。</p>
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
        try {
            long size = measureFrozenSize(sandbox, sandboxId, path, required);
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
                int expected = (int) Math.min(ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES,
                        size - (long) block * ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES);
                // head -c 冻结前缀：文件在读取期间变长时仍只取本块预期字节。
                String command = "dd if=" + path + " bs=" + ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES
                        + " skip=" + block + " count=1 2>/dev/null"
                        + " | head -c " + expected
                        + " | base64 | tr -d '\\r\\n'";
                CommandResult chunk = sandbox.command(sandboxId, new CommandRequest(
                        command, ExternalArtifactPaths.WORKING_DIRECTORY, Duration.ofSeconds(15),
                        ExternalArtifactPaths.SANDBOX_UID, ExternalArtifactPaths.SANDBOX_GID));
                if (chunk.exitCode() != 0) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED",
                            "trace block command failed"
                                    + detailSuffix(chunk.exitCode(), chunk.stderr()),
                            null);
                }
                String encoded = chunk.stdout() == null ? "" : chunk.stdout().replaceAll("\\s+", "");
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException malformed) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED", "trace block is not valid Base64", malformed);
                }
                if (decoded.length != expected) {
                    throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                            "TRACE_READ_FAILED",
                            "trace block length mismatch (block=" + block
                                    + " expected=" + expected
                                    + " actual=" + decoded.length
                                    + "; file may have shrunk or been truncated during read)",
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
        }
    }

    private static long measureFrozenSize(SandboxRuntimeClient sandbox, String sandboxId,
                                          String path, boolean required) {
        int attempts = required ? MISSING_TRACE_ATTEMPTS : 1;
        CommandResult last = null;
        for (int attempt = 0; attempt < attempts; attempt++) {
            // 不 cp 整文件：避免轨迹接近 tmpfs 上限时 ENOSPC。
            // 必需文件缺失用独立哨兵，便于与「尺寸命令失败」区分。
            String sizeCommand = required
                    ? "if [ ! -f " + path + " ]; then printf 'MISSING\\n'; exit 3; fi; "
                    + "wc -c < " + path
                    : "if [ -f " + path + " ]; then wc -c < " + path
                    + "; else printf '0\\n'; fi";
            CommandResult sizeResult = sandbox.command(sandboxId, new CommandRequest(
                    sizeCommand, ExternalArtifactPaths.WORKING_DIRECTORY, Duration.ofSeconds(20),
                    ExternalArtifactPaths.SANDBOX_UID, ExternalArtifactPaths.SANDBOX_GID));
            last = sizeResult;
            String sizeText = sizeResult.stdout() == null ? "" : sizeResult.stdout().strip();
            if (sizeResult.exitCode() == 3 || "MISSING".equals(sizeText)) {
                if (attempt + 1 < attempts) {
                    sleepBackoff();
                    continue;
                }
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_READ_FAILED",
                        "required Agent trace file is missing at " + path,
                        null);
            }
            if (sizeResult.exitCode() != 0 || !sizeText.matches("[0-9]{1,10}")) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_READ_FAILED",
                        "trace size could not be read"
                                + detailSuffix(sizeResult.exitCode(), sizeResult.stderr())
                                + (sizeText.isBlank() ? "" : "; stdout=" + truncate(sizeText, 80)),
                        null);
            }
            return Long.parseLong(sizeText);
        }
        throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                "TRACE_READ_FAILED",
                "trace size could not be read"
                        + (last == null ? "" : detailSuffix(last.exitCode(), last.stderr())),
                null);
    }

    private static void sleepBackoff() {
        long waitMillis = missingBackoffMillis();
        if (waitMillis <= 0L) {
            return;
        }
        try {
            Thread.sleep(waitMillis);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "TRACE_READ_FAILED", "trace read interrupted while waiting for file", interrupted);
        }
    }

    /** 测试可设 {@code veyrion.traceRead.missingBackoffMillis=0} 跳过等待。 */
    private static long missingBackoffMillis() {
        String override = System.getProperty("veyrion.traceRead.missingBackoffMillis");
        if (override == null || override.isBlank()) {
            return MISSING_TRACE_BACKOFF_MILLIS;
        }
        try {
            return Math.max(0L, Long.parseLong(override.strip()));
        } catch (NumberFormatException ignored) {
            return MISSING_TRACE_BACKOFF_MILLIS;
        }
    }

    private static String detailSuffix(int exitCode, String stderr) {
        String err = stderr == null ? "" : stderr.replaceAll("\\s+", " ").strip();
        if (err.length() > 160) {
            err = err.substring(0, 160);
        }
        StringBuilder detail = new StringBuilder(" (exit=").append(exitCode);
        if (!err.isBlank()) {
            detail.append("; stderr=").append(err);
            String lower = err.toLowerCase();
            if (lower.contains("no space left") || lower.contains("enospc")) {
                detail.append("; likely tmpfs exhausted — avoid full-file snapshot copies");
            }
        }
        detail.append(')');
        return detail.toString();
    }

    private static String truncate(String value, int max) {
        if (value == null || value.length() <= max) {
            return value == null ? "" : value;
        }
        return value.substring(0, max);
    }
}
