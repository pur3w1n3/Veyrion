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
    private static final Set<String> SENSITIVE_FRAGMENTS = Set.of(
            "authorization", "password", "passwd", "secret", "token", "cookie",
            "credential", "apikey", "api_key", "session");

    private final FileChannel channel;
    private final long maxBytes;
    private final int maxEvents;
    private final AtomicBoolean stopped = new AtomicBoolean();
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
        if (stopped.get()) return false;
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
        if (sequence >= maxEvents || encoded.length > maxBytes - bytesWritten) {
            writeBudgetExhaustedOnce();
            stopped.set(true);
            return false;
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(false);
            bytesWritten += encoded.length;
            sequence++;
            return true;
        } catch (IOException exception) {
            stopped.set(true);
            closeQuietly();
            return false;
        }
    }

    /** One visible gap event so control-plane / AI do not invent "no instrumentation". */
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
                + "\"maxBytes\":\"" + maxBytes + "\"}"
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
            // Fail-closed; caller still stops the writer.
        }
    }

    boolean isStopped() {
        return stopped.get();
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
            // The writer is already fail-closed.
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
