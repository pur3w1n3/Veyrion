package com.aq.jvmsentinel.instrumentation;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

final class EventWriter implements AutoCloseable {
    private static final int MAX_CLASS_LENGTH = 256;
    private static final int MAX_METHOD_LENGTH = 128;
    private static final int MAX_DETAIL_ENTRIES = 16;
    private static final int MAX_DETAIL_KEY_LENGTH = 64;
    private static final int MAX_DETAIL_VALUE_LENGTH = 256;
    /**
     * 全局池内单 correlation 软上限（与控制面 {@code EVENTS_PER_PROBE=2500} 对齐）。
     * 聊天/XSS 洪泛不得在耗尽全局 maxEvents 前饿死后半程探针。
     */
    static final int SOFT_CAP_EVENTS_PER_CORRELATION = 2_500;
    /**
     * 全局 maxEvents 耗尽后，每个 correlationId 仍允许少量非 EFFECT 事件，
     * 避免后期探针只剩 ENTRY_HIT、业务 hop 全被饿死。
     */
    static final int POST_BUDGET_EVENTS_PER_CORRELATION = 128;
    /** 与 {@code MAX_PROBE_PLAN_ENTRIES=512} 对齐，覆盖满探针计划的后续续写。 */
    static final int POST_BUDGET_CORRELATION_CAP = 512;
    private static final Set<String> SENSITIVE_FRAGMENTS = Set.of(
            "authorization", "password", "passwd", "secret", "token", "cookie",
            "credential", "apikey", "api_key", "session");

    private final FileChannel channel;
    private final long maxBytes;
    private final int maxEvents;
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final Map<String, Integer> correlationUsed = new LinkedHashMap<>();
    private final Map<String, Integer> postBudgetUsed = new LinkedHashMap<>();
    private long bytesWritten;
    private long sequence;

    EventWriter(AgentConfig config) {
        try {
            if (java.nio.file.Files.exists(config.traceFile, LinkOption.NOFOLLOW_LINKS)
                    && java.nio.file.Files.size(config.traceFile) != 0) {
                throw new IllegalArgumentException("trace output file must be new or empty");
            }
            channel = FileChannel.open(config.traceFile,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
                    LinkOption.NOFOLLOW_LINKS);
        } catch (IOException exception) {
            throw new IllegalArgumentException("trace output cannot be opened", exception);
        }
        maxBytes = config.maxBytes;
        maxEvents = config.maxEvents;
    }

    boolean writeObserved(String eventType, String className, String methodName, Map<String, String> detail) {
        return write(eventType, "RUNTIME_OBSERVED", className, methodName, detail);
    }

    boolean writeInstrumented(String eventType, String className, String methodName, Map<String, String> detail) {
        return write(eventType, "AGENT_INSTRUMENTED", className, methodName, detail);
    }

    boolean writeApplication(String eventType, String className, String methodName, Map<String, String> detail) {
        return write(eventType, "APPLICATION_REPORTED", className, methodName, detail);
    }

    private synchronized boolean write(String eventType, String provenanceKind, String className,
                                       String methodName, Map<String, String> detail) {
        boolean criticalEffect = isCriticalEffect(eventType, detail);
        String correlationId = detail == null ? "" : detail.getOrDefault("correlationId", "");
        // 软分片：全局耗尽前，单 correlation 不得垄断池。
        if (!criticalEffect && !stopped.get() && exceedsSoftCap(correlationId)) {
            return false;
        }
        // 软停：洪泛耗尽 maxEvents 后仍保留危险 sink EFFECT；另按 correlation 保留有界 hop。
        if (stopped.get() && !criticalEffect && !allowPostBudget(correlationId)) {
            return false;
        }
        Map<String, String> sanitizedDetail = sanitizeDetail(detail);
        String line = "{"
                + "\"schemaVersion\":1,"
                + "\"sequence\":" + sequence + ","
                + "\"eventType\":\"" + json(eventType) + "\","
                + "\"provenanceKind\":\"" + provenanceKind + "\","
                + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"" + json(sanitize(className, MAX_CLASS_LENGTH)) + "\","
                + "\"method\":\"" + json(sanitize(methodName, MAX_METHOD_LENGTH)) + "\","
                + "\"timestamp\":\"" + Instant.now() + "\","
                + "\"thread\":\"" + json(sanitize(Thread.currentThread().getName(), MAX_METHOD_LENGTH)) + "\","
                + "\"detail\":" + detailJson(sanitizedDetail)
                + "}\n";
        byte[] encoded = line.getBytes(StandardCharsets.UTF_8);
        if (!criticalEffect && !stopped.get()
                && (sequence >= maxEvents || encoded.length > maxBytes - bytesWritten)) {
            writeBudgetExhaustedOnce();
            stopped.set(true);
            if (!allowPostBudget(correlationId)) {
                return false;
            }
        }
        if (encoded.length > maxBytes - bytesWritten) {
            return false;
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(false);
            bytesWritten += encoded.length;
            sequence++;
            if (!criticalEffect) {
                consumeSoftCap(correlationId);
                if (stopped.get()) {
                    consumePostBudget(correlationId);
                }
            }
            return true;
        } catch (IOException exception) {
            stopped.set(true);
            closeQuietly();
            return false;
        }
    }

    /** 全局池内：单 correlation 已达软上限则让路（无 correlation 不软限，靠全局计数）。 */
    private boolean exceedsSoftCap(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return false;
        }
        if (correlationUsed.size() >= POST_BUDGET_CORRELATION_CAP
                && !correlationUsed.containsKey(correlationId)) {
            return true;
        }
        return correlationUsed.getOrDefault(correlationId, 0) >= SOFT_CAP_EVENTS_PER_CORRELATION;
    }

    private void consumeSoftCap(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return;
        }
        if (correlationUsed.size() >= POST_BUDGET_CORRELATION_CAP
                && !correlationUsed.containsKey(correlationId)) {
            return;
        }
        correlationUsed.put(correlationId, correlationUsed.getOrDefault(correlationId, 0) + 1);
    }

    /** 预算耗尽后按 correlation 的有界续写配额（无 correlation 不放行）。 */
    private boolean allowPostBudget(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return false;
        }
        if (postBudgetUsed.size() >= POST_BUDGET_CORRELATION_CAP
                && !postBudgetUsed.containsKey(correlationId)) {
            return false;
        }
        return postBudgetUsed.getOrDefault(correlationId, 0) < POST_BUDGET_EVENTS_PER_CORRELATION;
    }

    private void consumePostBudget(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return;
        }
        postBudgetUsed.put(correlationId, postBudgetUsed.getOrDefault(correlationId, 0) + 1);
    }

    /** 一条可见 gap 事件，以免 control-plane / AI 捏造「无插桩」。 */
    private void writeBudgetExhaustedOnce() {
        if (stopped.get()) {
            return;
        }
        String line = "{"
                + "\"schemaVersion\":1,"
                + "\"sequence\":" + sequence + ","
                + "\"eventType\":\"INSTRUMENTATION_CAPABILITY\","
                + "\"provenanceKind\":\"AGENT_INSTRUMENTED\","
                + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"com.aq.jvmsentinel.instrumentation.EventWriter\","
                + "\"method\":\"write\","
                + "\"timestamp\":\"" + Instant.now() + "\","
                + "\"thread\":\"" + json(sanitize(Thread.currentThread().getName(), MAX_METHOD_LENGTH)) + "\","
                + "\"detail\":{\"pathDebugKind\":\"TRACE_BUDGET_EXHAUSTED\","
                + "\"captureMode\":\"AGENT_BUDGET\",\"maxEvents\":\"" + maxEvents + "\","
                + "\"maxBytes\":\"" + maxBytes + "\","
                + "\"softCapPerCorrelation\":\"" + SOFT_CAP_EVENTS_PER_CORRELATION + "\","
                + "\"postBudgetPerCorrelation\":\"" + POST_BUDGET_EVENTS_PER_CORRELATION + "\"}"
                + "}\n";
        byte[] encoded = line.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > maxBytes - bytesWritten) {
            return;
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(false);
            bytesWritten += encoded.length;
            sequence++;
        } catch (IOException ignored) {
            // Fail-closed；调用方仍停止 writer。
        }
    }

    boolean isStopped() {
        return stopped.get();
    }

    /**
     * 危险 sink 效果：预算耗尽后仍允许写入，避免 FORCED 后半程探针
     * 仅剩 LOOPBACK HTTP、丢失 ExpressRunner/反序列化观测。
     * 仅 {@code pathDebugKind=EFFECT_TRIGGERED}（及同细节的 JDBC 语句）——
     * 普通 PROCESS/HTTP 洪泛不得绕过 maxEvents。
     */
    static boolean isCriticalEffect(String eventType, Map<String, String> detail) {
        if (detail == null) {
            return false;
        }
        if ("EFFECT_TRIGGERED".equals(detail.getOrDefault("pathDebugKind", ""))) {
            return true;
        }
        String type = eventType == null ? "" : eventType;
        if ("JDBC".equals(type)) {
            String capture = detail.getOrDefault("captureMode", "");
            String sql = detail.getOrDefault("sql", "");
            // 真实语句/connect；协议 listen meta 不保留。
            return ("DEPENDENCY_MOCK".equals(capture) || "IMPLEMENTATION_METHOD".equals(capture)
                    || "APPLICATION_CALL_SITE".equals(capture)
                    || "DATASOURCE_METHOD".equals(capture))
                    && (!sql.isBlank() || detail.containsKey("url")
                    || "connect".equalsIgnoreCase(detail.getOrDefault("operation", ""))
                    || "setUrl".equalsIgnoreCase(detail.getOrDefault("operation", ""))
                    || "getConnection".equalsIgnoreCase(detail.getOrDefault("operation", "")));
        }
        return false;
    }

    @Override
    public synchronized void close() throws IOException {
        stopped.set(true);
        channel.close();
    }

    private void closeQuietly() {
        try {
            channel.close();
        } catch (IOException ignored) {
            // Writer 已处于 fail-closed。
        }
    }

    private static Map<String, String> sanitizeDetail(Map<String, String> detail) {
        Map<String, String> result = new LinkedHashMap<>();
        if (detail == null) return result;
        int count = 0;
        for (Map.Entry<String, String> entry : detail.entrySet()) {
            if (count++ >= MAX_DETAIL_ENTRIES) break;
            String key = sanitize(entry.getKey(), MAX_DETAIL_KEY_LENGTH);
            if (key.isEmpty()) key = "field";
            String value = isSensitive(key)
                    ? "[REDACTED]"
                    : sanitize(entry.getValue(), MAX_DETAIL_VALUE_LENGTH);
            result.putIfAbsent(key, value);
        }
        return result;
    }

    private static boolean isSensitive(String key) {
        String normalized = key.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        for (String fragment : SENSITIVE_FRAGMENTS) {
            String candidate = fragment.replace("_", "");
            if (normalized.contains(candidate)) return true;
        }
        return false;
    }

    private static String sanitize(String value, int maximumLength) {
        if (value == null) return "";
        StringBuilder result = new StringBuilder(Math.min(value.length(), maximumLength));
        int consumed = 0;
        for (int offset = 0; offset < value.length() && consumed < maximumLength; ) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            consumed++;
            if (Character.isISOControl(codePoint) || Character.getType(codePoint) == Character.FORMAT) {
                result.append(' ');
            } else {
                result.appendCodePoint(codePoint);
            }
        }
        return result.toString();
    }

    private static String detailJson(Map<String, String> detail) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : detail.entrySet()) {
            if (!first) json.append(',');
            first = false;
            json.append('"').append(json(entry.getKey())).append("\":\"")
                    .append(json(entry.getValue())).append('"');
        }
        return json.append('}').toString();
    }

    private static String json(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int offset = 0; offset < value.length(); ) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            switch (codePoint) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                default -> {
                    if (codePoint < 0x20) {
                        escaped.append(String.format("\\u%04x", codePoint));
                    } else {
                        escaped.appendCodePoint(codePoint);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
