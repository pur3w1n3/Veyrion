package com.aq.jvmsentinel.agent;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fixed loopback-only HTTP stimulus used inside the deny-all Docker container.
 *
 * <p>Single: {@code method route [port] [query]}.</p>
 * <p>Batch: {@code --batch planFile port}; legacy {@code @planFile port} remains accepted.
 * A fixed {@code @planFile#port} argument keeps the plan and port in one shell token;
 * {@code @planFile} alone falls back to a fixed property or sibling {@code http-port.txt}.
 * Each plan line is
 * {@code METHOD\troute[\tquery[\ttrack[\tauthHeader[\tbladeAuthHeader[\texperimentPlanId[\tcookieHeader]]]]]]}.
 * Authorization, Blade-Auth, and Cookie are independent channels — a non-blank
 * {@code authHeader} does not imply {@code Blade-Auth} or Cookie, and vice versa.</p>
 *
 * <p>Batch uses a dual-phase strategy: a fast parallel pass (800ms connect/read),
 * then a capped slow retry (2000ms) for {@code BUSINESS_TIMEOUT} targets,
 * prioritizing {@code UNAUTH} so AUTH_CHALLENGE / HTTP outcomes are recovered
 * without reverting to full sequential 2s walls.</p>
 */
public final class LoopbackHttpProbe {
    private static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final int MAX_BATCH_LINES = 512;
    private static final int FAST_CONNECT_TIMEOUT_MS = 800;
    private static final int FAST_READ_TIMEOUT_MS = 800;
    private static final int SLOW_CONNECT_TIMEOUT_MS = 2000;
    private static final int SLOW_READ_TIMEOUT_MS = 2000;
    /** Wave-2 budget: recover timed-out high-value / UNAUTH observations. */
    private static final int MAX_SLOW_RETRIES = 128;
    private static final int DEFAULT_BATCH_THREADS = 8;
    private static final int MAX_BATCH_THREADS = 16;
    private static final byte[] SYNTHETIC_BODY =
            "{\"marker\":\"synthetic-http-entry-v1\"}".getBytes(StandardCharsets.US_ASCII);
    /** Local sequences inside probe-events.jsonl; the worker renumbers when merging. */
    private static final AtomicLong PROBE_SEQUENCE = new AtomicLong();
    private static int writtenEvents;
    private static int writeFailures;

    private LoopbackHttpProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && "--batch".equals(args[0])) {
            int code = runBatch(Path.of(args[1]), Integer.parseInt(args[2]));
            if (code != 0) System.exit(code);
            return;
        }
        if (args.length == 2 && args[0].startsWith("@")) {
            int code = runBatch(Path.of(args[0].substring(1)), Integer.parseInt(args[1]));
            if (code != 0) System.exit(code);
            return;
        }
        if (args.length == 1 && args[0].startsWith("@")) {
            String specification = args[0].substring(1);
            int delimiter = specification.lastIndexOf('#');
            Path planFile = Path.of(delimiter > 0
                    ? specification.substring(0, delimiter) : specification);
            int port = delimiter > 0
                    ? parseHttpPort(specification.substring(delimiter + 1), "embedded batch port")
                    : readConfiguredHttpPort(planFile);
            int code = runBatch(planFile, port);
            if (code != 0) System.exit(code);
            return;
        }
        if (args.length < 2 || args.length > 4) {
            throw new IllegalArgumentException(
                    "method route [port] [query], --batch planFile port, or legacy @planFile port"
                            + " are required (received " + args.length + " arguments)");
        }
        String method = args[0].toUpperCase(Locale.ROOT);
        String route = args[1];
        int port = args.length >= 3 ? Integer.parseInt(args[2]) : 8080;
        String query = args.length >= 4 ? args[3] : "";
        lastBatchPort = port;
        ProbeAttempt attempt = probeOne(method, route, port, query, "UNAUTH", "", "", "", "",
                FAST_CONNECT_TIMEOUT_MS, FAST_READ_TIMEOUT_MS, 1);
        writeAttemptEvent(attempt);
        if (attempt.status < 0) System.exit(2);
    }

    static int readConfiguredHttpPort(Path planFile) throws Exception {
        String configured = System.getProperty("veyrion.loopbackProbe.port");
        if (configured != null && !configured.isBlank()) {
            return parseHttpPort(configured, "veyrion.loopbackProbe.port");
        }
        String traceDirectory = System.getProperty("veyrion.sandbox.traceDir");
        if (traceDirectory != null && !traceDirectory.isBlank()) {
            return readHttpPortFile(
                    Path.of(traceDirectory).toAbsolutePath().normalize().resolve("http-port.txt"),
                    "trace directory http-port.txt");
        }
        return readSiblingHttpPort(planFile);
    }

    static int readSiblingHttpPort(Path planFile) throws Exception {
        return readHttpPortFile(
                planFile.toAbsolutePath().normalize().resolveSibling("http-port.txt"),
                "sibling http-port.txt");
    }

    private static int readHttpPortFile(Path portFile, String source) throws Exception {
        if (!Files.isRegularFile(portFile) || Files.isSymbolicLink(portFile)
                || Files.size(portFile) < 1 || Files.size(portFile) > 16) {
            throw new IllegalArgumentException(source + " is missing or invalid");
        }
        String value = Files.readString(portFile, StandardCharsets.US_ASCII).strip();
        return parseHttpPort(value, source);
    }

    private static int parseHttpPort(String value, String source) {
        if (value == null || !value.matches("[0-9]{1,5}")) {
            throw new IllegalArgumentException(source + " is not a TCP port");
        }
        int port = Integer.parseInt(value);
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException(source + " is outside the TCP port range");
        }
        return port;
    }

    /**
     * Batch probe entry. Returns process-style exit codes: 0 ok, 2 all failed, 3 zero events.
     */
    static int runBatch(Path planFile, int port) throws Exception {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("port is invalid");
        List<String> lines = Files.readAllLines(planFile, StandardCharsets.UTF_8);
        if (lines.isEmpty() || lines.size() > MAX_BATCH_LINES) {
            throw new IllegalArgumentException("probe plan size is outside limits");
        }
        List<ProbeTarget> targets = new ArrayList<>(lines.size());
        int ordinal = 0;
        for (String line : lines) {
            if (line == null || line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split("\t", -1);
            if (parts.length < 2 || parts.length > 8) {
                throw new IllegalArgumentException("probe plan line is invalid");
            }
            ordinal++;
            targets.add(new ProbeTarget(
                    parts[0].trim(),
                    parts[1].trim(),
                    parts.length >= 3 ? parts[2].trim() : "",
                    parts.length >= 4 && !parts[3].isBlank() ? parts[3].trim() : "UNAUTH",
                    parts.length >= 5 ? parts[4].trim() : "",
                    parts.length >= 6 ? parts[5].trim() : "",
                    parts.length >= 7 ? parts[6].trim() : "",
                    parts.length >= 8 ? parts[7].trim() : "",
                    ordinal));
        }
        if (targets.isEmpty()) throw new IllegalArgumentException("probe plan is empty");
        writtenEvents = 0;
        writeFailures = 0;
        lastBatchPort = port;
        int concurrency = Math.min(targets.size(), batchConcurrency());
        writeProgress("批量探测启动：" + targets.size() + " 个目标，并发 " + concurrency
                + "（快波 " + FAST_READ_TIMEOUT_MS + "ms，慢重试上限 " + MAX_SLOW_RETRIES + "）");

        List<ProbeAttempt> wave1 = runWave(targets, port, concurrency,
                FAST_CONNECT_TIMEOUT_MS, FAST_READ_TIMEOUT_MS, "快波");

        List<ProbeAttempt> timedOut = new ArrayList<>();
        int failures = 0;
        for (ProbeAttempt attempt : wave1) {
            if (attempt.businessTimeout()) {
                timedOut.add(attempt);
            } else {
                writeAttemptEvent(attempt);
                if (attempt.status < 0) failures++;
            }
        }

        List<ProbeAttempt> retrySelected = selectSlowRetryTargets(timedOut, MAX_SLOW_RETRIES);
        Set<Integer> retryOrdinals = new HashSet<>();
        for (ProbeAttempt selected : retrySelected) {
            retryOrdinals.add(selected.target.ordinal);
        }
        for (ProbeAttempt attempt : timedOut) {
            if (!retryOrdinals.contains(attempt.target.ordinal)) {
                writeAttemptEvent(attempt);
                failures++;
            }
        }

        if (!retrySelected.isEmpty()) {
            List<ProbeTarget> retryTargets = new ArrayList<>(retrySelected.size());
            for (ProbeAttempt selected : retrySelected) {
                retryTargets.add(selected.target);
            }
            writeProgress("慢波重试：" + retryTargets.size() + "/" + timedOut.size()
                    + " 个 BUSINESS_TIMEOUT（优先 UNAUTH，超时 "
                    + SLOW_READ_TIMEOUT_MS + "ms）");
            int slowConcurrency = Math.min(retryTargets.size(), concurrency);
            List<ProbeAttempt> wave2 = runWave(retryTargets, port, slowConcurrency,
                    SLOW_CONNECT_TIMEOUT_MS, SLOW_READ_TIMEOUT_MS, "慢波");
            for (ProbeAttempt attempt : wave2) {
                writeAttemptEvent(attempt);
                if (attempt.status < 0) failures++;
            }
        }

        writeProgress("批量探测完成：" + (targets.size() - failures) + "/" + targets.size()
                + " 收到 HTTP 响应；写入事件 " + writtenEvents
                + (writeFailures == 0 ? "" : "（写失败 " + writeFailures + "）")
                + "；慢波重试 " + retrySelected.size());
        if (writtenEvents == 0) {
            System.err.println("LoopbackHttpProbe wrote zero HTTP events");
            return 3;
        }
        if (failures == targets.size()) return 2;
        return 0;
    }

    private static List<ProbeAttempt> runWave(List<ProbeTarget> targets, int port, int concurrency,
                                              int connectTimeoutMs, int readTimeoutMs,
                                              String waveLabel) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<ProbeAttempt>> futures = new ArrayList<>(targets.size());
        for (ProbeTarget target : targets) {
            futures.add(executor.submit(() -> {
                writeProgress(waveLabel + "探测 " + target.ordinal + ": " + target.method + " "
                        + target.route + " [" + target.track + "]"
                        + (target.query.isEmpty() ? "" : "?" + target.query));
                return probeOne(target.method, target.route, port, target.query, target.track,
                        target.authHeader, target.bladeAuthHeader, target.experimentPlanId,
                        target.cookieHeader,
                        connectTimeoutMs, readTimeoutMs, target.ordinal);
            }));
        }
        executor.shutdown();
        List<ProbeAttempt> attempts = new ArrayList<>(targets.size());
        try {
            for (Future<ProbeAttempt> future : futures) {
                attempts.add(future.get());
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        }
        return attempts;
    }

    /**
     * Prefer UNAUTH timeouts (auth discrimination), then other tracks; stable by ordinal; hard cap.
     */
    static List<ProbeAttempt> selectSlowRetryTargets(List<ProbeAttempt> timedOut, int maxRetries) {
        if (timedOut == null || timedOut.isEmpty() || maxRetries <= 0) return List.of();
        List<ProbeAttempt> ranked = new ArrayList<>(timedOut);
        ranked.sort(Comparator
                .comparingInt((ProbeAttempt a) -> trackRetryRank(a.target.track))
                .thenComparingInt(a -> a.target.ordinal));
        if (ranked.size() <= maxRetries) return List.copyOf(ranked);
        return List.copyOf(ranked.subList(0, maxRetries));
    }

    static int trackRetryRank(String track) {
        if (track == null) return 99;
        return switch (track) {
            case "UNAUTH" -> 0;
            case "USER" -> 1;
            case "ADMIN" -> 2;
            case "BYPASS_CANDIDATE" -> 3;
            default -> 50;
        };
    }

    private static ProbeAttempt probeOne(String rawMethod, String route, int port, String query,
                                         String track, String authHeader, String bladeAuthHeader,
                                         String experimentPlanId, String cookieHeader,
                                         int connectTimeoutMs, int readTimeoutMs, int ordinal) {
        ProbeTarget target = new ProbeTarget(
                rawMethod == null ? "" : rawMethod,
                route == null ? "" : route,
                query == null ? "" : query,
                track == null || track.isBlank() ? "UNAUTH" : track,
                authHeader == null ? "" : authHeader,
                bladeAuthHeader == null ? "" : bladeAuthHeader,
                experimentPlanId == null ? "" : experimentPlanId,
                cookieHeader == null ? "" : cookieHeader,
                ordinal);
        String method = target.method.toUpperCase(Locale.ROOT);
        if (!METHODS.contains(method)
                || route == null
                || !route.matches("/[A-Za-z0-9_./{}:-]{0,1023}")
                || port < 1 || port > 65535
                || (query != null && !query.isEmpty()
                && !query.matches("[A-Za-z0-9_=&%./{}:-]{1,256}"))
                || (track != null && !track.matches("[A-Z_]{1,32}"))
                || (authHeader != null && authHeader.length() > 2048)
                || (bladeAuthHeader != null && bladeAuthHeader.length() > 2048)
                || (cookieHeader != null && cookieHeader.length() > 2048)) {
            return new ProbeAttempt(target, -1, "InvalidTarget",
                    route == null ? "" : route, connectTimeoutMs, readTimeoutMs, "");
        }
        String requestTarget = target.query.isEmpty() ? target.route : target.route + "?" + target.query;
        byte[] body = Set.of("POST", "PUT", "PATCH").contains(method)
                ? SYNTHETIC_BODY : new byte[0];
        String correlationId = "req-" + target.ordinal + "-"
                + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        int status = -1;
        String error = "";
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            OutputStream output = socket.getOutputStream();
            String headerBlock = buildRequestHeaders(method, requestTarget, body.length,
                    target.authHeader, target.bladeAuthHeader, correlationId,
                    target.track, target.experimentPlanId, target.cookieHeader);
            output.write(headerBlock.getBytes(StandardCharsets.US_ASCII));
            output.write(body);
            output.flush();
            InputStream input = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int total = 0;
            int read;
            StringBuilder head = new StringBuilder();
            while (total < MAX_RESPONSE_BYTES
                    && (read = input.read(buffer, 0,
                    Math.min(buffer.length, MAX_RESPONSE_BYTES - total))) >= 0) {
                total += read;
                if (status < 0 && head.length() < 128) {
                    head.append(new String(buffer, 0, read, StandardCharsets.ISO_8859_1));
                    int lineEnd = head.indexOf("\r\n");
                    if (lineEnd > 0) {
                        status = parseStatus(head.substring(0, lineEnd));
                    }
                }
            }
        } catch (Exception failure) {
            error = failure.getClass().getSimpleName();
            status = -1;
        }
        return new ProbeAttempt(target, status, error, requestTarget, connectTimeoutMs, readTimeoutMs,
                correlationId);
    }

    /**
     * Builds the HTTP request head. Authorization and Blade-Auth are independent:
     * neither channel is copied from the other.
     */
    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader) {
        return buildRequestHeaders(method, requestTarget, contentLength, authHeader, bladeAuthHeader, null);
    }

    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader, String correlationId) {
        return buildRequestHeaders(method, requestTarget, contentLength, authHeader, bladeAuthHeader,
                correlationId, "UNAUTH", "", "");
    }

    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader, String correlationId,
                                      String track, String experimentPlanId) {
        return buildRequestHeaders(method, requestTarget, contentLength, authHeader, bladeAuthHeader,
                correlationId, track, experimentPlanId, "");
    }

    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader, String correlationId,
                                      String track, String experimentPlanId, String cookieHeader) {
        StringBuilder headers = new StringBuilder();
        headers.append(method).append(' ').append(requestTarget).append(" HTTP/1.1\r\n")
                .append("Host: 127.0.0.1\r\nConnection: close\r\n")
                .append("Content-Type: application/json\r\n")
                .append("Content-Length: ").append(contentLength).append("\r\n");
        if (correlationId != null && !correlationId.isBlank()) {
            headers.append("X-Veyrion-Correlation-Id: ").append(correlationId).append("\r\n");
        }
        String posture = postureHeaderForTrack(track, experimentPlanId);
        if (!posture.isBlank()) {
            headers.append("X-Veyrion-Runtime-Posture: ").append(posture).append("\r\n");
        }
        if (authHeader != null && !authHeader.isBlank()) {
            headers.append("Authorization: bearer ").append(authHeader).append("\r\n");
        }
        if (bladeAuthHeader != null && !bladeAuthHeader.isBlank()) {
            headers.append("Blade-Auth: ").append(bladeAuthHeader).append("\r\n");
        }
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            headers.append("Cookie: ").append(cookieHeader).append("\r\n");
        }
        headers.append("\r\n");
        return headers.toString();
    }

    static String postureHeaderForTrack(String track, String experimentPlanId) {
        if (experimentPlanId != null && experimentPlanId.toUpperCase(Locale.ROOT).contains("FORCED")) {
            return "FORCED_REACHABILITY";
        }
        if (track == null || track.isBlank()) {
            return "UNAUTH";
        }
        return switch (track.trim().toUpperCase(Locale.ROOT)) {
            case "UNAUTH" -> "UNAUTH";
            case "BYPASS_CANDIDATE" -> "BYPASS";
            case "ADMIN", "USER" -> "COVERAGE_POSTURE";
            default -> "UNAUTH";
        };
    }

    private static void writeAttemptEvent(ProbeAttempt attempt) {
        String outcome = classifyOutcome(attempt.status, attempt.error);
        String method = attempt.target.method.toUpperCase(Locale.ROOT);
        System.out.println(method + " " + attempt.requestTarget
                + " -> HTTP "
                + (attempt.status < 0 ? "UNKNOWN" : Integer.toString(attempt.status))
                + " (" + outcome + ", track=" + attempt.target.track
                + ", port " + lastBatchPort + ")"
                + (attempt.error.isEmpty() ? "" : "; " + attempt.error));
        writeProbeEvent(method, attempt.target.route, lastBatchPort, attempt.status,
                attempt.requestTarget, attempt.error, outcome, attempt.target.track,
                attempt.correlationId, attempt.target.experimentPlanId);
    }

    /**
     * Probe-side entry hit: true when the HTTP response shows the route reached the app or auth
     * layer; false for missing/unsupported methods; absent ({@code null}) for transport failures.
     */
    static Boolean classifyEntryHit(int httpStatus) {
        if (httpStatus == 404 || httpStatus == 405) return Boolean.FALSE;
        if (httpStatus == 401 || httpStatus == 403) return Boolean.TRUE;
        if (httpStatus >= 200 && httpStatus < 400) return Boolean.TRUE;
        return null;
    }

    /**
     * Probe alone cannot prove binding success. Only emit false for clear no-route cases.
     */
    static Boolean classifyParameterBound(int httpStatus) {
        if (httpStatus == 404 || httpStatus == 405) return Boolean.FALSE;
        return null;
    }

    static String classifyOutcome(int httpStatus, String errorClass) {
        String error = errorClass == null ? "" : errorClass;
        if ("InvalidTarget".equals(error)) return "UNKNOWN";
        if (error.contains("SocketTimeout")) return "BUSINESS_TIMEOUT";
        if (error.contains("ConnectException")) return "COLD_START";
        if (error.contains("SocketException") || error.contains("EOFException")) {
            return "TRANSPORT_ERROR";
        }
        if (httpStatus == 401 || httpStatus == 403) return "AUTH_CHALLENGE";
        if (httpStatus == 404) return "REACHED_NO_BIND";
        if (httpStatus == 409 || httpStatus == 423 || httpStatus == 429) return "ENGINE_BUSY";
        if (httpStatus == 500 || httpStatus == 502 || httpStatus == 503) {
            return "DEPENDENCY_MOCK_GAP";
        }
        if (httpStatus >= 200 && httpStatus < 500) return "HTTP_OBSERVED";
        if (httpStatus < 0) return "UNKNOWN";
        return "UNKNOWN";
    }

    private static synchronized void writeProbeEvent(String method, String route, int port, int status,
                                                     String requestTarget, String error, String outcomeClass,
                                                     String track, String correlationId,
                                                     String experimentPlanId) {
        try {
            String dir = System.getProperty("veyrion.sandbox.traceDir");
            if (dir == null || dir.isBlank()) {
                writeFailures++;
                return;
            }
            Path file = Path.of(dir, "probe-events.jsonl");
            long sequence = PROBE_SEQUENCE.getAndIncrement();
            String statusText = status < 0 ? "UNKNOWN" : Integer.toString(status);
            String verification = "DYNAMIC_SUSPECTED";
            Boolean entryHit = classifyEntryHit(status);
            Boolean parameterBound = classifyParameterBound(status);
            StringBuilder detail = new StringBuilder();
            detail.append("\"captureMode\":\"LOOPBACK_HTTP_PROBE\",")
                    .append("\"httpMethod\":\"").append(json(truncate(method, 16))).append("\",")
                    .append("\"route\":\"").append(json(truncate(route, 512))).append("\",")
                    .append("\"requestTarget\":\"").append(json(truncate(requestTarget, 512))).append("\",")
                    .append("\"status\":\"").append(json(statusText)).append("\",")
                    .append("\"port\":\"").append(port).append("\",")
                    .append("\"error\":\"").append(json(truncate(error == null ? "" : error, 64))).append("\",")
                    .append("\"outcomeClass\":\"").append(json(truncate(outcomeClass, 32))).append("\",")
                    .append("\"track\":\"").append(json(truncate(track == null ? "UNAUTH" : track, 32))).append("\"");
            if (correlationId != null && !correlationId.isBlank()) {
                detail.append(",\"correlationId\":\"").append(json(truncate(correlationId, 64))).append("\"");
            }
            if (experimentPlanId != null && !experimentPlanId.isBlank()) {
                detail.append(",\"experimentPlanId\":\"")
                        .append(json(truncate(experimentPlanId, 128))).append("\"");
            }
            if (entryHit != null) {
                detail.append(",\"entryHit\":\"").append(entryHit ? "true" : "false").append("\"");
            }
            if (parameterBound != null) {
                detail.append(",\"parameterBound\":\"").append(parameterBound ? "true" : "false").append("\"");
            }
            String line = "{"
                    + "\"schemaVersion\":1,"
                    + "\"sequence\":" + sequence + ","
                    + "\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\","
                    + "\"verificationStatus\":\"" + verification + "\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\","
                    + "\"method\":\"main\","
                    + "\"timestamp\":\"" + Instant.now() + "\","
                    + "\"thread\":\"" + json(Thread.currentThread().getName()) + "\","
                    + "\"detail\":{" + detail + "}}\n";
            Files.writeString(file, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            writtenEvents++;
        } catch (Exception failure) {
            writeFailures++;
            System.err.println("LoopbackHttpProbe could not write probe event: "
                    + failure.getClass().getSimpleName());
        }
    }

    /** Port for single-shot main / console lines; batch sets this before waves. */
    private static volatile int lastBatchPort = 0;

    private static void writeProgress(String message) {
        try {
            String dir = System.getProperty("veyrion.sandbox.traceDir");
            if (dir == null || dir.isBlank()) return;
            Files.writeString(Path.of(dir, "progress.txt"), message + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception ignored) {
        }
    }

    private static int batchConcurrency() {
        String configured = System.getProperty("veyrion.loopbackProbe.threads");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("VEYRION_PROBE_THREADS");
        }
        int value = DEFAULT_BATCH_THREADS;
        if (configured != null && !configured.isBlank()) {
            try {
                value = Integer.parseInt(configured.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return Math.max(1, Math.min(MAX_BATCH_THREADS, value));
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static String json(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.toString();
    }

    private static int parseStatus(String statusLine) {
        String[] parts = statusLine.split(" ", 3);
        if (parts.length < 2) return -1;
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    static final class ProbeTarget {
        final String method;
        final String route;
        final String query;
        final String track;
        final String authHeader;
        final String bladeAuthHeader;
        final String experimentPlanId;
        final String cookieHeader;
        final int ordinal;

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, int ordinal) {
            this(method, route, query, track, authHeader, "", "", "", ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, int ordinal) {
            this(method, route, query, track, authHeader, bladeAuthHeader, "", "", ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, String experimentPlanId, int ordinal) {
            this(method, route, query, track, authHeader, bladeAuthHeader, experimentPlanId, "", ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, String experimentPlanId,
                    String cookieHeader, int ordinal) {
            this.method = method;
            this.route = route;
            this.query = query;
            this.track = track;
            this.authHeader = authHeader == null ? "" : authHeader;
            this.bladeAuthHeader = bladeAuthHeader == null ? "" : bladeAuthHeader;
            this.experimentPlanId = experimentPlanId == null ? "" : experimentPlanId;
            this.cookieHeader = cookieHeader == null ? "" : cookieHeader;
            this.ordinal = ordinal;
        }
    }

    static final class ProbeAttempt {
        final ProbeTarget target;
        final int status;
        final String error;
        final String requestTarget;
        final int connectTimeoutMs;
        final int readTimeoutMs;
        final String correlationId;

        ProbeAttempt(ProbeTarget target, int status, String error, String requestTarget,
                     int connectTimeoutMs, int readTimeoutMs) {
            this(target, status, error, requestTarget, connectTimeoutMs, readTimeoutMs, "");
        }

        ProbeAttempt(ProbeTarget target, int status, String error, String requestTarget,
                     int connectTimeoutMs, int readTimeoutMs, String correlationId) {
            this.target = target;
            this.status = status;
            this.error = error == null ? "" : error;
            this.requestTarget = requestTarget == null ? "" : requestTarget;
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
            this.correlationId = correlationId == null ? "" : correlationId;
        }

        boolean businessTimeout() {
            return status < 0 && error.contains("SocketTimeout");
        }
    }
}
