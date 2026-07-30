package com.aq.jvmsentinel.worker.probe;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 校验 loopback HTTP 探针 JSONL 是否覆盖已提交的探针计划。
 */
public final class ProbeEvidenceValidator {
    private static final String LOOPBACK_PROBE_CLASS = "com.aq.jvmsentinel.agent.LoopbackHttpProbe";
    private static final int MAX_MISSING_IN_MESSAGE = 8;

    private ProbeEvidenceValidator() { }

    /**
     * 洪泛/沙箱计划必须产生至少一条 HTTP 探针事件。单目标超时仍算成功（有证据）；
     * 非空计划却零事件则 fail-closed。
     *
     * <p>覆盖按 wire identity（method/route/requestTarget/track）比对；expected 的
     * requestTarget 使用与 LoopbackHttpProbe 相同的 body/query 规则，避免 form/multipart
     * 假阴性。{@code expected.size()==observed.size()} 仍可能因集合成员不同而失败。</p>
     *
     * <p>末行 JSON 截断（{@code truncatedTail}）且覆盖不全时抛
     * {@code PROBE_EVENT_EVIDENCE_TRUNCATED}，不得标成真实 {@code PROBE_EVENT_COVERAGE_INCOMPLETE}。</p>
     */
    public static void requireHttpProbeEvidence(ExternalArtifactTaskExecutor.ArtifactRegistration registration,
                                         byte[] mergedJsonl) {
        Objects.requireNonNull(registration, "registration");
        Objects.requireNonNull(mergedJsonl, "mergedJsonl");
        if (registration.probePlan() == null || registration.probePlan().isEmpty()) return;

        Set<String> expected = registration.probePlan().stream()
                .map(target -> probeIdentity(
                        target.method(),
                        target.route(),
                        ProbeWireTarget.requestTarget(target.method(), target.route(), target.query()),
                        target.track()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> observed = new LinkedHashSet<>();
        int httpEvents = 0;
        int loopbackProbeEvents = 0;
        boolean skippedTruncatedTail = false;
        String[] lines = new String(mergedJsonl, StandardCharsets.UTF_8).split("\n", -1);
        int lastNonBlank = -1;
        for (int i = 0; i < lines.length; i++) {
            if (!lines[i].isBlank()) lastNonBlank = i;
        }
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.isBlank()) continue;
            Map<String, Object> event;
            try {
                event = JsonCodec.parseObject(line);
            } catch (RuntimeException malformed) {
                // 大轨迹末尾截断的半行不整文件判死；中间损坏仍 fail-closed。
                if (i == lastNonBlank && (httpEvents > 0 || loopbackProbeEvents > 0 || !observed.isEmpty())) {
                    skippedTruncatedTail = true;
                    continue;
                }
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "MALFORMED_PROBE_EVENTS",
                        "loopback HTTP probe events are not valid JSONL"
                                + (i == lastNonBlank ? " (truncated trailing line)" : " at line " + (i + 1)),
                        malformed);
            }
            if (!"HTTP".equals(event.get("eventType"))) continue;
            httpEvents++;
            if (!LOOPBACK_PROBE_CLASS.equals(event.get("class"))
                    || !(event.get("detail") instanceof Map<?, ?> detail)) {
                continue;
            }
            // Agent 仪器 HTTP 不得冒充 loopback probe；要求 captureMode 或至少有 route。
            Object captureMode = detail.get("captureMode");
            if (captureMode != null && !"LOOPBACK_HTTP_PROBE".equals(String.valueOf(captureMode))) {
                continue;
            }
            loopbackProbeEvents++;
            observed.add(probeIdentity(
                    Objects.toString(detail.get("httpMethod"), ""),
                    Objects.toString(detail.get("route"), ""),
                    Objects.toString(detail.get("requestTarget"), ""),
                    Objects.toString(detail.get("track"), "")));
        }
        if (observed.containsAll(expected)) return;
        Set<String> missing = new LinkedHashSet<>(expected);
        missing.removeAll(observed);
        // 尾部半行截断时，缺项可能是假阴性（证据预算/tmpfs 写断），不得标成真实未覆盖。
        String code;
        if (loopbackProbeEvents == 0) {
            code = "EMPTY_PROBE_EVENTS";
        } else if (skippedTruncatedTail) {
            code = "PROBE_EVENT_EVIDENCE_TRUNCATED";
        } else {
            code = "PROBE_EVENT_COVERAGE_INCOMPLETE";
        }
        throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(code,
                "loopback HTTP probe evidence does not cover the submitted plan (expected="
                        + expected.size() + ", observed=" + observed.size()
                        + ", loopbackProbeEvents=" + loopbackProbeEvents
                        + ", httpEvents=" + httpEvents
                        + (skippedTruncatedTail ? ", truncatedTail=true" : "")
                        + ", missing=" + missing.size()
                        + ": " + formatMissing(missing) + ")",
                null);
    }

    public static int countHttpEvents(byte[] jsonl) {
        if (jsonl == null || jsonl.length == 0) return 0;
        int count = 0;
        for (String line : new String(jsonl, StandardCharsets.UTF_8).split("\n", -1)) {
            if (line.contains("\"eventType\":\"HTTP\"")) count++;
        }
        return count;
    }

    private static String probeIdentity(String method, String route, String requestTarget, String track) {
        String trackValue = track == null || track.isBlank() ? "UNAUTH" : track;
        return method.toUpperCase(Locale.ROOT) + '\u0000' + route + '\u0000'
                + requestTarget + '\u0000' + trackValue;
    }

    private static String formatMissing(Set<String> missing) {
        if (missing.isEmpty()) return "(none)";
        List<String> parts = new ArrayList<>();
        int n = 0;
        for (String id : missing) {
            if (n >= MAX_MISSING_IN_MESSAGE) {
                parts.add("…+" + (missing.size() - MAX_MISSING_IN_MESSAGE) + " more");
                break;
            }
            parts.add(readableIdentity(id));
            n++;
        }
        return String.join("; ", parts);
    }

    private static String readableIdentity(String identity) {
        String[] parts = identity.split("\u0000", -1);
        if (parts.length < 4) return identity;
        return parts[0] + " " + parts[2] + " track=" + parts[3];
    }
}
