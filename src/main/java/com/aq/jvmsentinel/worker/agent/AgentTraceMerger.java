package com.aq.jvmsentinel.worker.agent;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 合并进程内 agent JSONL 与进程外 loopback 探针 JSONL。
 */
public final class AgentTraceMerger {
    private AgentTraceMerger() { }

    /**
     * 在 in-app agent JSONL 之后追加 loopback 探针事件，重编号 sequence，
     * 使 {@link com.aq.jvmsentinel.worker.AgentJsonlTraceConverter} 看到连续流。
     */
    public static byte[] mergeProbeEvents(byte[] agentJsonl, byte[] probeJsonl) {
        Objects.requireNonNull(agentJsonl, "agentJsonl");
        if (probeJsonl == null || probeJsonl.length == 0) return agentJsonl;
        String agentText = new String(agentJsonl, StandardCharsets.UTF_8);
        String probeText = new String(probeJsonl, StandardCharsets.UTF_8).trim();
        if (probeText.isEmpty()) return agentJsonl;
        long nextSequence = 0;
        for (String line : agentText.split("\n", -1)) {
            if (line.isBlank()) continue;
            int marker = line.indexOf("\"sequence\":");
            if (marker < 0) continue;
            int start = marker + "\"sequence\":".length();
            int end = start;
            while (end < line.length() && Character.isDigit(line.charAt(end))) end++;
            if (end > start) {
                nextSequence = Math.max(nextSequence, Long.parseLong(line.substring(start, end)) + 1);
            }
        }
        StringBuilder merged = new StringBuilder(agentText);
        if (!agentText.isEmpty() && !agentText.endsWith("\n")) merged.append('\n');
        for (String line : probeText.split("\n", -1)) {
            if (line.isBlank()) continue;
            int marker = line.indexOf("\"sequence\":");
            if (marker < 0) continue;
            int start = marker + "\"sequence\":".length();
            int end = start;
            while (end < line.length() && Character.isDigit(line.charAt(end))) end++;
            if (end <= start) continue;
            merged.append(line, 0, start).append(nextSequence++).append(line, end, line.length());
            if (!line.endsWith("\n")) merged.append('\n');
        }
        return merged.toString().getBytes(StandardCharsets.UTF_8);
    }
}
