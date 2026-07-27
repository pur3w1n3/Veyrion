package com.aq.jvmsentinel.worker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Converts the bounded {@code agent-jsonl-v1} stream into immutable Worker trace chunks.
 *
 * <p>The converter validates but does not semantically rewrite events. Payloads retain the
 * complete input lines, normalizing only line endings to a single LF.</p>
 */
public final class AgentJsonlTraceConverter {
    private static final Set<String> FIELDS = Set.of(
            "schemaVersion", "sequence", "eventType", "provenanceKind", "verificationStatus",
            "class", "method", "timestamp", "thread", "detail");
    private static final Set<String> EVENT_TYPES = Set.of(
            "AGENT_STARTED", "INSTRUMENTATION_CAPABILITY", "INSTRUMENTATION_ERROR",
            "CLASS_LOAD", "HTTP", "HTTP_CLIENT", "FILE", "JDBC", "PROCESS", "BRANCH_COVERAGE");
    private static final Set<String> PROVENANCE_KINDS =
            Set.of("RUNTIME_OBSERVED", "AGENT_INSTRUMENTED", "APPLICATION_REPORTED");

    private final Clock clock;
    private final Limits limits;

    public AgentJsonlTraceConverter(Clock clock, Limits limits) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.limits = Objects.requireNonNull(limits, "limits");
    }

    public AgentJsonlTraceConverter(Clock clock, long maxTotalBytes, int maxLineBytes,
                                    int maxLines, int maxChunkPayloadBytes) {
        this(clock, new Limits(maxTotalBytes, maxLineBytes, maxLines, maxChunkPayloadBytes));
    }

    public List<TraceChunk> convert(byte[] input, TaskScope scope, ResourceBudget budget) {
        Objects.requireNonNull(input, "input");
        if (input.length > limits.maxTotalBytes()) {
            throw new IllegalArgumentException("agent JSONL exceeds total byte limit");
        }
        try {
            return convert(new ByteArrayInputStream(input), scope, budget);
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory JSONL read failed", impossible);
        }
    }

    public List<TraceChunk> convert(InputStream input, TaskScope scope, ResourceBudget budget)
            throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(budget, "budget");

        ArrayList<TraceChunk> chunks = new ArrayList<>();
        ByteArrayOutputStream line = new ByteArrayOutputStream(
                Math.min(limits.maxLineBytes(), 8192));
        ByteArrayOutputStream chunk = new ByteArrayOutputStream(
                Math.min(limits.maxChunkPayloadBytes(), 8192));
        long inputBytes = 0;
        long payloadBytes = 0;
        long expectedEventSequence = 0;
        int lineCount = 0;
        long chunkSequence = 0;
        String previousDigest = null;
        boolean lastWasLf = false;

        int next;
        while ((next = input.read()) != -1) {
            if (inputBytes >= limits.maxTotalBytes()) {
                throw new IllegalArgumentException("agent JSONL exceeds total byte limit");
            }
            inputBytes++;
            if (next == '\n') {
                if (line.size() == 0) throw new IllegalArgumentException("empty JSONL line");
                byte[] rawLine = line.toByteArray();
                int contentLength = rawLine.length;
                if (rawLine[contentLength - 1] == '\r') contentLength--;
                if (contentLength == 0) throw new IllegalArgumentException("empty JSONL line");
                expectedEventSequence = Math.addExact(
                        parseAcceptedLine(rawLine, contentLength, expectedEventSequence).sequence(), 1);
                lineCount = incrementLineCount(lineCount);
                payloadBytes = addPayloadBytes(payloadBytes, contentLength + 1L, budget.maxTraceBytes());
                if (contentLength + 1 > limits.maxChunkPayloadBytes()) {
                    throw new IllegalArgumentException("single JSONL line exceeds chunk payload limit");
                }
                if (chunk.size() > limits.maxChunkPayloadBytes() - (contentLength + 1)) {
                    TraceChunk emitted = emit(scope, chunkSequence++, previousDigest, chunk);
                    chunks.add(emitted);
                    previousDigest = emitted.digest();
                }
                chunk.write(rawLine, 0, contentLength);
                chunk.write('\n');
                line.reset();
                lastWasLf = true;
            } else {
                if (line.size() >= limits.maxLineBytes()) {
                    throw new IllegalArgumentException("agent JSONL line exceeds byte limit");
                }
                line.write(next);
                lastWasLf = false;
            }
        }

        if (line.size() > 0) {
            byte[] rawLine = line.toByteArray();
            int contentLength = rawLine.length;
            if (rawLine[contentLength - 1] == '\r') {
                throw new IllegalArgumentException("bare CR line ending is not allowed");
            }
            expectedEventSequence = Math.addExact(
                    parseAcceptedLine(rawLine, contentLength, expectedEventSequence).sequence(), 1);
            lineCount = incrementLineCount(lineCount);
            payloadBytes = addPayloadBytes(payloadBytes, contentLength + 1L, budget.maxTraceBytes());
            if (contentLength + 1 > limits.maxChunkPayloadBytes()) {
                throw new IllegalArgumentException("single JSONL line exceeds chunk payload limit");
            }
            if (chunk.size() > limits.maxChunkPayloadBytes() - (contentLength + 1)) {
                TraceChunk emitted = emit(scope, chunkSequence++, previousDigest, chunk);
                chunks.add(emitted);
                previousDigest = emitted.digest();
            }
            chunk.write(rawLine, 0, contentLength);
            chunk.write('\n');
        } else if (lineCount == 0 && !lastWasLf) {
            throw new IllegalArgumentException("agent JSONL must contain at least one event");
        }

        if (chunk.size() > 0) {
            chunks.add(emit(scope, chunkSequence, previousDigest, chunk));
        }
        return List.copyOf(chunks);
    }

    private int incrementLineCount(int current) {
        if (current >= limits.maxLines()) {
            throw new IllegalArgumentException("agent JSONL exceeds line count limit");
        }
        return current + 1;
    }

    private static long addPayloadBytes(long current, long added, long maximum) {
        if (added < 0 || current < 0 || current > maximum || added > maximum - current) {
            throw new IllegalArgumentException("agent JSONL exceeds trace byte budget");
        }
        return current + added;
    }

    private TraceChunk emit(TaskScope scope, long sequence, String previousDigest,
                            ByteArrayOutputStream payload) {
        TraceChunk result = TraceChunk.create(
                scope, sequence, previousDigest, clock.instant(), payload.toByteArray());
        payload.reset();
        return result;
    }

    /**
     * Strictly parses one converter-accepted agent-jsonl-v1 line.
     * The returned event contains immutable values and never retains the input buffer.
     */
    public static AgentEvent parseAcceptedLine(byte[] rawLine, int length, long expectedSequence) {
        Objects.requireNonNull(rawLine, "rawLine");
        if (length <= 0 || length > rawLine.length) {
            throw new IllegalArgumentException("invalid JSONL line length");
        }
        for (int i = 0; i < length; i++) {
            int value = rawLine[i] & 0xff;
            if (value < 0x20 || value == 0x7f) {
                throw new IllegalArgumentException("raw control character in JSONL line");
            }
        }
        String json = decodeUtf8(rawLine, length);
        Map<String, Object> event = new Parser(json).parseObjectDocument();
        if (!event.keySet().equals(FIELDS)) {
            throw new IllegalArgumentException("agent event fields do not match agent-jsonl-v1");
        }
        requireLong(event, "schemaVersion", 1);
        requireLong(event, "sequence", expectedSequence);
        requireStringIn(event, "eventType", EVENT_TYPES);
        requireStringIn(event, "provenanceKind", PROVENANCE_KINDS);
        requireString(event, "verificationStatus", "DYNAMIC_SUSPECTED");
        for (String field : List.of("class", "method", "timestamp", "thread")) {
            if (!(event.get(field) instanceof String)) {
                throw new IllegalArgumentException(field + " must be a JSON string");
            }
        }
        Object detail = event.get("detail");
        if (!(detail instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("detail must be a JSON object");
        }
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof String)) {
                throw new IllegalArgumentException("detail fields must have string values");
            }
        }
        if (expectedSequence == Long.MAX_VALUE) {
            throw new IllegalArgumentException("agent sequence overflow");
        }
        @SuppressWarnings("unchecked")
        Map<String, String> details = (Map<String, String>) detail;
        return new AgentEvent(
                ((Long) event.get("sequence")),
                (String) event.get("eventType"),
                (String) event.get("provenanceKind"),
                (String) event.get("verificationStatus"),
                (String) event.get("class"),
                (String) event.get("method"),
                (String) event.get("timestamp"),
                (String) event.get("thread"),
                Map.copyOf(details));
    }

    private static String decodeUtf8(byte[] value, int length) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value, 0, length))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("agent JSONL contains malformed UTF-8", exception);
        }
    }

    private static void requireLong(Map<String, Object> event, String field, long expected) {
        Object value = event.get(field);
        if (!(value instanceof Long number) || number != expected) {
            throw new IllegalArgumentException(field + " has an invalid value");
        }
    }

    private static void requireString(Map<String, Object> event, String field, String expected) {
        Object value = event.get(field);
        if (!(value instanceof String text) || !text.equals(expected)) {
            throw new IllegalArgumentException(field + " has an invalid value");
        }
    }

    private static void requireStringIn(Map<String, Object> event, String field, Set<String> allowed) {
        Object value = event.get(field);
        if (!(value instanceof String text) || !allowed.contains(text)) {
            throw new IllegalArgumentException(field + " has an invalid value");
        }
    }

    /** Independent ingestion limits supplied by trusted Worker configuration. */
    public record Limits(long maxTotalBytes, int maxLineBytes, int maxLines,
                         int maxChunkPayloadBytes) {
        public Limits {
            if (maxTotalBytes <= 0) throw new IllegalArgumentException("maxTotalBytes must be positive");
            if (maxLineBytes <= 0) throw new IllegalArgumentException("maxLineBytes must be positive");
            if (maxLines <= 0) throw new IllegalArgumentException("maxLines must be positive");
            if (maxChunkPayloadBytes <= 0
                    || maxChunkPayloadBytes > WorkerContracts.MAX_TRACE_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("maxChunkPayloadBytes is outside TraceChunk limits");
            }
        }
    }

    /** Immutable semantic view of one accepted Agent event. */
    public record AgentEvent(long sequence, String eventType, String provenanceKind,
                             String verificationStatus, String className, String method,
                             String timestamp, String thread, Map<String, String> detail) {
        public AgentEvent {
            detail = Map.copyOf(detail);
        }
    }

    private static final class Parser {
        private final String input;
        private int position;

        private Parser(String input) {
            this.input = input;
        }

        private Map<String, Object> parseObjectDocument() {
            skipSpaces();
            Map<String, Object> value = parseObject(false);
            skipSpaces();
            if (position != input.length()) throw error("trailing JSON data");
            return value;
        }

        private Map<String, Object> parseObject(boolean stringValuesOnly) {
            expect('{');
            LinkedHashMap<String, Object> result = new LinkedHashMap<>();
            skipSpaces();
            if (consume('}')) return result;
            while (true) {
                skipSpaces();
                String key = parseString();
                if (result.containsKey(key)) throw error("duplicate JSON object key");
                skipSpaces();
                expect(':');
                skipSpaces();
                Object value;
                if (stringValuesOnly) {
                    if (peek() != '"') throw error("detail value must be a string");
                    value = parseString();
                } else {
                    value = parseTopLevelValue(key);
                }
                result.put(key, value);
                skipSpaces();
                if (consume('}')) return result;
                expect(',');
            }
        }

        private Object parseTopLevelValue(String key) {
            char next = peek();
            if (next == '"') return parseString();
            if (next == '{' && key.equals("detail")) return parseObject(true);
            if ((next == '-' || next >= '0' && next <= '9')
                    && (key.equals("schemaVersion") || key.equals("sequence"))) {
                return parseInteger();
            }
            throw error("unsupported field type");
        }

        private Long parseInteger() {
            int start = position;
            consume('-');
            if (position >= input.length()) throw error("invalid integer");
            if (consume('0')) {
                if (position < input.length() && Character.isDigit(input.charAt(position))) {
                    throw error("leading zero in integer");
                }
            } else {
                char first = peek();
                if (first < '1' || first > '9') throw error("invalid integer");
                position++;
                while (position < input.length() && Character.isDigit(input.charAt(position))) {
                    position++;
                }
            }
            if (position < input.length()) {
                char suffix = input.charAt(position);
                if (suffix == '.' || suffix == 'e' || suffix == 'E') {
                    throw error("integer field cannot be fractional");
                }
            }
            try {
                return Long.parseLong(input.substring(start, position));
            } catch (NumberFormatException exception) {
                throw error("integer is out of range");
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (position < input.length()) {
                char value = input.charAt(position++);
                if (value == '"') {
                    validateString(result);
                    return result.toString();
                }
                if (value == '\\') {
                    if (position >= input.length()) throw error("unterminated escape");
                    char escaped = input.charAt(position++);
                    switch (escaped) {
                        case '"', '\\', '/' -> result.append(escaped);
                        case 'b' -> result.append('\b');
                        case 'f' -> result.append('\f');
                        case 'n' -> result.append('\n');
                        case 'r' -> result.append('\r');
                        case 't' -> result.append('\t');
                        case 'u' -> result.append(parseUnicodeEscape());
                        default -> throw error("invalid escape");
                    }
                } else {
                    if (value < 0x20) throw error("control character in string");
                    result.append(value);
                }
            }
            throw error("unterminated string");
        }

        private char parseUnicodeEscape() {
            if (position > input.length() - 4) throw error("short unicode escape");
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(input.charAt(position++), 16);
                if (digit < 0) throw error("invalid unicode escape");
                value = value * 16 + digit;
            }
            return (char) value;
        }

        private static void validateString(CharSequence value) {
            for (int offset = 0; offset < value.length(); ) {
                int codePoint = Character.codePointAt(value, offset);
                if (Character.isSurrogate(value.charAt(offset))
                        && (codePoint <= Character.MAX_VALUE
                        || !Character.isSurrogatePair(value.charAt(offset), value.charAt(offset + 1)))) {
                    throw new IllegalArgumentException("unpaired surrogate in JSON string");
                }
                int type = Character.getType(codePoint);
                if (Character.isISOControl(codePoint) || type == Character.FORMAT
                        || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR) {
                    throw new IllegalArgumentException("control character injection in JSON string");
                }
                offset += Character.charCount(codePoint);
            }
        }

        private void skipSpaces() {
            while (position < input.length() && input.charAt(position) == ' ') position++;
        }

        private char peek() {
            if (position >= input.length()) throw error("unexpected end of JSON");
            return input.charAt(position);
        }

        private boolean consume(char expected) {
            if (position < input.length() && input.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) throw error("expected '" + expected + "'");
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at character " + position);
        }
    }
}
