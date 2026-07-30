package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** 候选输入 → 有界洪水探针目标选择。 */
public final class ProbeFloodSelector {
    private ProbeFloodSelector() {
    }

    /**
     * 将 AI/调用方候选输入映射为有界 ProbeTarget 列表（最多 8 条）。
     *
     * @param entry 入口
     * @param candidateInputs 候选 query 片段（name=value 或裸值）
     * @param requestedMaxRequests 请求上限提示
     */
    public static List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbeTargets(
            ApiDtos.EntryDto entry, List<String> candidateInputs, int requestedMaxRequests) {
        if (candidateInputs == null || candidateInputs.isEmpty()) return List.of();
        int limit = Math.max(1, Math.min(8, requestedMaxRequests));
        List<String> parameterNames = entry.parameters() == null ? List.of() : entry.parameters().stream()
                .map(ProbeWireHelpers::parameterName).filter(Objects::nonNull).limit(12).toList();
        List<ExternalArtifactTaskExecutor.ProbeTarget> result = new ArrayList<>();
        for (String candidate : candidateInputs) {
            if (result.size() >= limit || candidate == null || candidate.length() > 1024) break;
            String name;
            String value;
            int separator = candidate.indexOf('=');
            if (separator > 0) {
                name = candidate.substring(0, separator);
                value = candidate.substring(separator + 1);
            } else if (!parameterNames.isEmpty()) {
                name = parameterNames.get(Math.min(result.size(), parameterNames.size() - 1));
                value = candidate;
            } else {
                continue;
            }
            if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") || value.length() > 512
                    || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)
                    || parameterNames.isEmpty() || !parameterNames.contains(name)) continue;
            String encoded = java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
            ExternalArtifactTaskExecutor.ProbeTarget surface = ProbeWireHelpers.probeTargetFor(entry);
            result.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    surface.method(),
                    surface.route(),
                    name + "=" + encoded,
                    "UNAUTH",
                    "",
                    "",
                    "",
                    "",
                    surface.listenPort()));
        }
        return List.copyOf(result);
    }
}
