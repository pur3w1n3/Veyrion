package com.aq.jvmsentinel.worker.probe;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 校验 loopback HTTP 探针 JSONL 是否覆盖已提交的探针计划。
 */
public final class ProbeEvidenceValidator {
    private ProbeEvidenceValidator() { }

    /**
     * 洪泛/沙箱计划必须产生至少一条 HTTP 探针事件。单目标超时仍算成功（有证据）；
     * 非空计划却零事件则 fail-closed。
     */
    public static void requireHttpProbeEvidence(ExternalArtifactTaskExecutor.ArtifactRegistration registration,
                                         byte[] mergedJsonl) {
        Objects.requireNonNull(registration, "registration");
        Objects.requireNonNull(mergedJsonl, "mergedJsonl");
        if (registration.probePlan() == null || registration.probePlan().isEmpty()) return;

        Set<String> expected = registration.probePlan().stream()
                .map(target -> probeIdentity(target.method(), target.route(),
                        target.query().isBlank() ? target.route() : target.route() + "?" + target.query(),
                        target.track()))
                .collect(Collectors.toSet());
        Set<String> observed = new java.util.HashSet<>();
        int httpEvents = 0;
        try {
            for (String line : new String(mergedJsonl, StandardCharsets.UTF_8).split("\n", -1)) {
                if (line.isBlank()) continue;
                Map<String, Object> event = JsonCodec.parseObject(line);
                if (!"HTTP".equals(event.get("eventType"))) continue;
                httpEvents++;
                if (!"com.aq.jvmsentinel.agent.LoopbackHttpProbe".equals(event.get("class"))
                        || !(event.get("detail") instanceof Map<?, ?> detail)) {
                    continue;
                }
                observed.add(probeIdentity(
                        Objects.toString(detail.get("httpMethod"), ""),
                        Objects.toString(detail.get("route"), ""),
                        Objects.toString(detail.get("requestTarget"), ""),
                        Objects.toString(detail.get("track"), "")));
            }
        } catch (RuntimeException malformed) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "MALFORMED_PROBE_EVENTS", "loopback HTTP probe events are not valid JSONL", malformed);
        }
        if (observed.containsAll(expected)) return;
        String code = httpEvents == 0 ? "EMPTY_PROBE_EVENTS" : "PROBE_EVENT_COVERAGE_INCOMPLETE";
        throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(code,
                "loopback HTTP probe evidence does not cover the submitted plan (expected="
                        + expected.size() + ", observed=" + observed.size()
                        + ", httpEvents=" + httpEvents + ")",
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
        return method.toUpperCase(java.util.Locale.ROOT) + '\u0000' + route + '\u0000'
                + requestTarget + '\u0000' + track;
    }
}
