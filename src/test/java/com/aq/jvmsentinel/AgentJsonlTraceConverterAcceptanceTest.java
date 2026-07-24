package com.aq.jvmsentinel;

import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TraceChunk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/** Dependency-free acceptance checks for bounded agent-jsonl-v1 conversion. */
public final class AgentJsonlTraceConverterAcceptanceTest {
    private static final Instant CONVERSION_TIME = Instant.parse("2026-07-24T06:00:00Z");
    private static final Clock CLOCK = Clock.fixed(CONVERSION_TIME, ZoneOffset.UTC);
    private static final TaskScope SCOPE =
            new TaskScope("project-1", "a".repeat(64), "scan-1", "task-1");

    public static void main(String[] args) throws Exception {
        convertsMultipleChunksAndChainsDigests();
        enforcesAllBoundaries();
        rejectsInvalidContractEvents();
        rejectsMalformedEncodingAndInjection();
        acceptsInputStreamWithoutBulkReads();
        System.out.println("AgentJsonlTraceConverterAcceptanceTest: PASS");
    }

    private static void convertsMultipleChunksAndChainsDigests() throws Exception {
        String first = event(0, "AGENT_STARTED", "RUNTIME_OBSERVED", "1900-01-01T00:00:00Z");
        String second = event(1, "CLASS_LOAD", "RUNTIME_OBSERVED", "2999-01-01T00:00:00Z");
        String third = event(2, "HTTP", "APPLICATION_REPORTED", "2000-01-01T00:00:00Z");
        int chunkLimit = Math.max(payloadLength(first), Math.max(payloadLength(second), payloadLength(third)));
        String input = first + "\r\n" + second + "\n" + third;
        AgentJsonlTraceConverter converter = converter(bytes(input).length, 4096, 3, chunkLimit);

        List<TraceChunk> chunks = converter.convert(
                new ByteArrayInputStream(bytes(input)), SCOPE, budget(Long.MAX_VALUE));

        check(chunks.size() == 3, "complete lines must be split into three chunks");
        String normalized = first + "\n" + second + "\n" + third + "\n";
        StringBuilder reconstructed = new StringBuilder();
        for (int i = 0; i < chunks.size(); i++) {
            TraceChunk chunk = chunks.get(i);
            check(chunk.sequence() == i, "chunk sequence must be contiguous");
            check(chunk.emittedAt().equals(CONVERSION_TIME), "event timestamp must not control chain time");
            check(i == 0 ? chunk.previousDigest() == null
                            : chunk.previousDigest().equals(chunks.get(i - 1).digest()),
                    "previous digest must link to prior chunk");
            check(chunk.digest().equals(TraceChunk.calculateDigest(
                            chunk.schemaVersion(), chunk.scope(), chunk.sequence(),
                            chunk.previousDigest(), chunk.emittedAt(), chunk.payload())),
                    "chunk digest must cover emitted content");
            reconstructed.append(new String(chunk.payload(), StandardCharsets.UTF_8));
        }
        check(reconstructed.toString().equals(normalized),
                "payload must preserve complete original lines and normalize them to LF");
    }

    private static void enforcesAllBoundaries() throws Exception {
        String one = event(0, "FILE", "APPLICATION_REPORTED", "2026-07-24T00:00:00Z");
        byte[] input = bytes(one + "\n");
        int lineBytes = bytes(one).length;
        int payloadBytes = input.length;

        check(converter(input.length, lineBytes, 1, payloadBytes)
                        .convert(input, SCOPE, budget(payloadBytes)).size() == 1,
                "exact total, line, count, chunk and trace limits must be accepted");
        reject(() -> converter(input.length - 1L, lineBytes, 1, payloadBytes)
                .convert(input, SCOPE, budget(payloadBytes)), "total byte overflow");
        reject(() -> converter(input.length, lineBytes - 1, 1, payloadBytes)
                .convert(input, SCOPE, budget(payloadBytes)), "line byte overflow");
        reject(() -> converter(input.length * 2L, lineBytes, 1, payloadBytes)
                .convert(bytes(one + "\n" + event(1, "FILE", "APPLICATION_REPORTED",
                        "2026-07-24T00:00:01Z") + "\n"), SCOPE, budget(Long.MAX_VALUE)),
                "line count overflow");
        reject(() -> converter(input.length, lineBytes, 1, payloadBytes - 1)
                .convert(input, SCOPE, budget(payloadBytes)), "single line chunk overflow");
        reject(() -> converter(input.length, lineBytes, 1, payloadBytes)
                .convert(input, SCOPE, budget(payloadBytes - 1L)), "trace budget overflow");
        reject(() -> new AgentJsonlTraceConverter.Limits(Long.MAX_VALUE, 1, 1, 1024 * 1024 + 1),
                "TraceChunk payload ceiling");
        reject(() -> converter(1024, 1024, 4, 1024)
                .convert(new byte[0], SCOPE, budget(1024)), "empty stream");
        reject(() -> converter(1024, 1024, 4, 1024)
                .convert(bytes("\n"), SCOPE, budget(1024)), "empty line");
    }

    private static void rejectsInvalidContractEvents() throws Exception {
        String valid = event(0, "JDBC", "APPLICATION_REPORTED", "2026-07-24T00:00:00Z");
        rejectJson("[]", "non-object JSON");
        rejectJson(valid + " {}", "multiple JSON values");
        rejectJson(valid.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
                "wrong schema version");
        rejectJson(valid.replace("\"sequence\":0", "\"sequence\":1"), "initial sequence jump");
        rejectJson(valid + "\n" + event(2, "JDBC", "APPLICATION_REPORTED",
                "2026-07-24T00:00:01Z"), "later sequence jump");
        rejectJson(valid.replace("DYNAMIC_SUSPECTED", "VERIFIED"), "VERIFIED status");
        rejectJson(valid.replace("APPLICATION_REPORTED", "STATIC_INFERRED"), "unknown provenance");
        rejectJson(valid.replace("\"eventType\":\"JDBC\"", "\"eventType\":\"SOCKET\""),
                "unknown event type");
        rejectJson(valid.replace("\"eventType\":\"JDBC\"", "\"eventType\":1"),
                "wrong known-field type");
        rejectJson(valid.replace("\"detail\":{}", "\"detail\":{\"count\":1}"),
                "wrong detail field type");
        rejectJson(valid.replace("\"detail\":{}", "\"extra\":true,\"detail\":{}"),
                "unknown field and type");
        rejectJson(valid.replace("{\"schemaVersion\":1",
                "{\"schemaVersion\":1,\"schemaVersion\":1"), "duplicate critical field");
        rejectJson(valid.replace("\"detail\":{}", "\"detail\":{\"key\":\"a\",\"key\":\"b\"}"),
                "duplicate detail field");
        rejectJson(valid.substring(0, valid.length() - 1), "malformed JSON");
    }

    private static void rejectsMalformedEncodingAndInjection() throws Exception {
        byte[] malformedUtf8 = bytes(event(0, "PROCESS", "APPLICATION_REPORTED",
                "2026-07-24T00:00:00Z"));
        int classValue = indexOf(malformedUtf8, bytes("\"Fixture\""));
        malformedUtf8[classValue + 1] = (byte) 0xc3;
        reject(() -> converter(4096, 4096, 4, 4096)
                .convert(malformedUtf8, SCOPE, budget(4096)), "malformed UTF-8");

        String valid = event(0, "PROCESS", "APPLICATION_REPORTED", "2026-07-24T00:00:00Z");
        rejectJson(valid.replace("\"Fixture\"", "\"bad\\nvalue\""),
                "escaped control character injection");
        rejectJson(valid.replace("\"class\":\"Fixture\"", "\"class\":\t\"Fixture\""),
                "raw control character injection");
        rejectJson(valid.replace("\"Fixture\"", "\"bad\\u2028value\""),
                "line separator injection");
        rejectJson(valid + "\r", "bare CR ending");
        rejectJson("\ufeff" + valid, "UTF-8 BOM");
    }

    private static void acceptsInputStreamWithoutBulkReads() throws Exception {
        byte[] input = bytes(event(0, "CLASS_LOAD", "RUNTIME_OBSERVED",
                "2026-07-24T00:00:00Z") + "\n");
        InputStream singleByteOnly = new ByteArrayInputStream(input) {
            @Override
            public int read(byte[] buffer, int offset, int length) {
                throw new AssertionError("converter must not use unbounded or bulk whole-stream reads");
            }
        };
        List<TraceChunk> chunks = converter(input.length, input.length, 1, input.length)
                .convert(singleByteOnly, SCOPE, budget(input.length));
        check(chunks.size() == 1, "single-byte streaming input must convert");
    }

    private static AgentJsonlTraceConverter converter(long total, int line, int lines, int chunk) {
        return new AgentJsonlTraceConverter(CLOCK, total, line, lines, chunk);
    }

    private static ResourceBudget budget(long traceBytes) {
        return new ResourceBudget(60, 10_000, 256 * 1024 * 1024L,
                64 * 1024 * 1024L, traceBytes);
    }

    private static String event(long sequence, String eventType, String provenance, String timestamp) {
        return "{\"schemaVersion\":1,\"sequence\":" + sequence
                + ",\"eventType\":\"" + eventType + "\""
                + ",\"provenanceKind\":\"" + provenance + "\""
                + ",\"verificationStatus\":\"DYNAMIC_SUSPECTED\""
                + ",\"class\":\"Fixture\",\"method\":\"run\""
                + ",\"timestamp\":\"" + timestamp + "\",\"thread\":\"main\",\"detail\":{}}";
    }

    private static int payloadLength(String line) {
        return bytes(line).length + 1;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        throw new AssertionError("test fixture token not found");
    }

    private static void rejectJson(String json, String message) throws Exception {
        byte[] input = bytes(json);
        reject(() -> converter(Math.max(1, input.length), Math.max(1, input.length), 8,
                Math.max(1, input.length + 1)).convert(input, SCOPE, budget(Math.max(1, input.length + 8L))),
                message);
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static void reject(ThrowingRunnable runnable, String message) throws Exception {
        try {
            runnable.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected rejection: " + message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws IOException;
    }
}
