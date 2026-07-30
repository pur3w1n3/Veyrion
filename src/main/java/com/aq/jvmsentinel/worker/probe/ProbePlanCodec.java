package com.aq.jvmsentinel.worker.probe;

import com.aq.jvmsentinel.worker.ExternalArtifactPaths;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 探针计划 TSV 序列化与 host 侧临时文件写入。
 */
public final class ProbePlanCodec {
    private ProbePlanCodec() { }

    /**
     * 将洪泛/探针计划序列化为 agent TSV 格式，并在 worker 上传前强制执行可信沙箱上传预算。
     */
    public static byte[] encodeProbePlan(List<ExternalArtifactTaskExecutor.ProbeTarget> targets) {
        List<ExternalArtifactTaskExecutor.ProbeTarget> plan = targets == null ? List.of() : targets;
        if (plan.size() > ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES) {
            throw new IllegalArgumentException("probe plan exceeds entry limit ("
                    + plan.size() + " > " + ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES + ")");
        }
        StringBuilder text = new StringBuilder(Math.min(64 * 1024, plan.size() * 64 + 16));
        for (ExternalArtifactTaskExecutor.ProbeTarget target : plan) {
            text.append(target.method()).append('\t').append(target.route()).append('\t')
                    .append(target.query() == null ? "" : target.query()).append('\t')
                    .append(target.track() == null ? "UNAUTH" : target.track()).append('\t')
                    .append(target.authHeader() == null ? "" : target.authHeader()).append('\t')
                    .append(target.bladeAuthHeader() == null ? "" : target.bladeAuthHeader());
            boolean hasCookie = target.cookieHeader() != null && !target.cookieHeader().isBlank();
            boolean hasPlan = target.experimentPlanId() != null && !target.experimentPlanId().isBlank();
            boolean hasListenPort = target.listenPort() > 0;
            if (hasPlan || hasCookie || hasListenPort) {
                text.append('\t').append(hasPlan ? target.experimentPlanId() : "");
            }
            if (hasCookie || hasListenPort) {
                text.append('\t').append(hasCookie ? target.cookieHeader() : "");
            }
            if (hasListenPort) {
                text.append('\t').append(target.listenPort());
            }
            text.append('\n');
        }
        byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > ExternalArtifactPaths.MAX_PROBE_PLAN_UPLOAD_BYTES) {
            throw new IllegalArgumentException(
                    "probe plan host file size exceeds trusted sandbox upload budget ("
                            + bytes.length + " > " + ExternalArtifactPaths.MAX_PROBE_PLAN_UPLOAD_BYTES + ")");
        }
        return bytes;
    }

    /** 序列化探针计划的 UTF-8 字节数；空计划为 0。 */
    public static int probePlanUtf8Bytes(List<ExternalArtifactTaskExecutor.ProbeTarget> targets) {
        List<ExternalArtifactTaskExecutor.ProbeTarget> plan = targets == null ? List.of() : targets;
        if (plan.isEmpty()) return 0;
        int total = 0;
        for (ExternalArtifactTaskExecutor.ProbeTarget target : plan) {
            total += target.method().getBytes(StandardCharsets.UTF_8).length + 1;
            total += target.route().getBytes(StandardCharsets.UTF_8).length + 1;
            String query = target.query() == null ? "" : target.query();
            total += query.getBytes(StandardCharsets.UTF_8).length + 1;
            String track = target.track() == null || target.track().isBlank() ? "UNAUTH" : target.track();
            total += track.getBytes(StandardCharsets.UTF_8).length + 1;
            String auth = target.authHeader() == null ? "" : target.authHeader();
            total += auth.getBytes(StandardCharsets.UTF_8).length + 1;
            String blade = target.bladeAuthHeader() == null ? "" : target.bladeAuthHeader();
            total += blade.getBytes(StandardCharsets.UTF_8).length + 1;
            boolean hasCookie = target.cookieHeader() != null && !target.cookieHeader().isBlank();
            boolean hasPlan = target.experimentPlanId() != null && !target.experimentPlanId().isBlank();
            boolean hasListenPort = target.listenPort() > 0;
            if (hasPlan || hasCookie || hasListenPort) {
                String planId = hasPlan ? target.experimentPlanId() : "";
                total += planId.getBytes(StandardCharsets.UTF_8).length + 1;
            }
            if (hasCookie || hasListenPort) {
                String cookie = hasCookie ? target.cookieHeader() : "";
                total += cookie.getBytes(StandardCharsets.UTF_8).length + 1;
            }
            if (hasListenPort) {
                total += Integer.toString(target.listenPort()).getBytes(StandardCharsets.UTF_8).length + 1;
            }
        }
        return total;
    }

    public static Path writeHostProbePlan(List<ExternalArtifactTaskExecutor.ProbeTarget> targets) {
        try {
            Path file = Files.createTempFile("veyrion-probe-plan-", ".txt");
            Files.write(file, encodeProbePlan(targets));
            return file;
        } catch (IllegalArgumentException invalid) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "PROBE_PLAN_TOO_LARGE", invalid.getMessage(), invalid);
        } catch (IOException failure) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "PROBE_PLAN_WRITE_FAILED", "probe plan could not be written on the host", failure);
        }
    }
}
