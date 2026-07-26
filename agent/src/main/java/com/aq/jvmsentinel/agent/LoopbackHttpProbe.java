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
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fixed loopback-only HTTP stimulus used inside the deny-all Docker container.
 *
 * <p>Single: {@code method route [port] [query]}.</p>
 * <p>Batch: {@code @planFile port} where each plan line is {@code METHOD\troute[\tquery]}.</p>
 */
public final class LoopbackHttpProbe {
    private static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final int MAX_BATCH_LINES = 512;
    private static final byte[] SYNTHETIC_BODY =
            "{\"marker\":\"synthetic-http-entry-v1\"}".getBytes(StandardCharsets.US_ASCII);
    /** Local sequences inside probe-events.jsonl; the worker renumbers when merging. */
    private static final AtomicLong PROBE_SEQUENCE = new AtomicLong();

    private LoopbackHttpProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].startsWith("@")) {
            runBatch(Path.of(args[0].substring(1)), Integer.parseInt(args[1]));
            return;
        }
        if (args.length < 2 || args.length > 4) {
            throw new IllegalArgumentException(
                    "method route [port] [query], or @planFile port, are required");
        }
        String method = args[0].toUpperCase(Locale.ROOT);
        String route = args[1];
        int port = args.length >= 3 ? Integer.parseInt(args[2]) : 8080;
        String query = args.length >= 4 ? args[3] : "";
        int status = probeOne(method, route, port, query);
        if (status < 0) System.exit(2);
    }

    private static void runBatch(Path planFile, int port) throws Exception {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("port is invalid");
        List<String> lines = Files.readAllLines(planFile, StandardCharsets.UTF_8);
        if (lines.isEmpty() || lines.size() > MAX_BATCH_LINES) {
            throw new IllegalArgumentException("probe plan size is outside limits");
        }
        List<String[]> targets = new ArrayList<>(lines.size());
        for (String line : lines) {
            if (line == null || line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split("\t", -1);
            if (parts.length < 2 || parts.length > 3) {
                throw new IllegalArgumentException("probe plan line is invalid");
            }
            targets.add(new String[]{
                    parts[0].trim(),
                    parts[1].trim(),
                    parts.length == 3 ? parts[2].trim() : ""
            });
        }
        if (targets.isEmpty()) throw new IllegalArgumentException("probe plan is empty");
        int failures = 0;
        for (int i = 0; i < targets.size(); i++) {
            String[] target = targets.get(i);
            writeProgress("批量探测 " + (i + 1) + "/" + targets.size()
                    + ": " + target[0] + " " + target[1]
                    + (target[2].isEmpty() ? "" : "?" + target[2]));
            if (probeOne(target[0], target[1], port, target[2]) < 0) failures++;
        }
        writeProgress("批量探测完成：" + (targets.size() - failures) + "/" + targets.size() + " 收到 HTTP 响应");
        if (failures == targets.size()) System.exit(2);
    }

    private static int probeOne(String rawMethod, String route, int port, String query) {
        String method = rawMethod == null ? "" : rawMethod.toUpperCase(Locale.ROOT);
        if (!METHODS.contains(method)
                || route == null
                || !route.matches("/[A-Za-z0-9_./{}:-]{0,1023}")
                || port < 1 || port > 65535
                || (query != null && !query.isEmpty()
                && !query.matches("[A-Za-z0-9_=&%./{}:-]{1,256}"))) {
            writeProbeEvent(method, route == null ? "" : route, port, -1,
                    route == null ? "" : route, "InvalidTarget");
            return -1;
        }
        String requestTarget = (query == null || query.isEmpty()) ? route : route + "?" + query;
        byte[] body = Set.of("POST", "PUT", "PATCH").contains(method)
                ? SYNTHETIC_BODY : new byte[0];
        int status = -1;
        String error = "";
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), 2_000);
            socket.setSoTimeout(2_000);
            OutputStream output = socket.getOutputStream();
            String headers = method + " " + requestTarget + " HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\nConnection: close\r\n"
                    + "Content-Type: application/json\r\nContent-Length: " + body.length + "\r\n\r\n";
            output.write(headers.getBytes(StandardCharsets.US_ASCII));
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
        String detail = method + " " + requestTarget + " → HTTP "
                + (status < 0 ? "UNKNOWN" : Integer.toString(status))
                + " (port " + port + ")"
                + (error.isEmpty() ? "" : "; " + error);
        System.out.println(detail);
        writeProbeEvent(method, route, port, status, requestTarget, error);
        return status;
    }

    private static void writeProbeEvent(String method, String route, int port, int status,
                                        String requestTarget, String error) {
        try {
            String dir = System.getProperty("veyrion.sandbox.traceDir");
            if (dir == null || dir.isBlank()) return;
            Path file = Path.of(dir, "probe-events.jsonl");
            long sequence = PROBE_SEQUENCE.getAndIncrement();
            String statusText = status < 0 ? "UNKNOWN" : Integer.toString(status);
            String line = "{"
                    + "\"schemaVersion\":1,"
                    + "\"sequence\":" + sequence + ","
                    + "\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\","
                    + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\","
                    + "\"method\":\"main\","
                    + "\"timestamp\":\"" + Instant.now() + "\","
                    + "\"thread\":\"" + json(Thread.currentThread().getName()) + "\","
                    + "\"detail\":{"
                    + "\"captureMode\":\"LOOPBACK_HTTP_PROBE\","
                    + "\"httpMethod\":\"" + json(truncate(method, 16)) + "\","
                    + "\"route\":\"" + json(truncate(route, 512)) + "\","
                    + "\"requestTarget\":\"" + json(truncate(requestTarget, 512)) + "\","
                    + "\"status\":\"" + json(statusText) + "\","
                    + "\"port\":\"" + port + "\","
                    + "\"error\":\"" + json(truncate(error == null ? "" : error, 64)) + "\""
                    + "}}\n";
            Files.writeString(file, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // Probe success is independent of evidence file write.
        }
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
        String[] parts = statusLine.trim().split("\\s+");
        if (parts.length < 2) return -1;
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private static void writeProgress(String message) {
        try {
            String dir = System.getProperty("veyrion.sandbox.traceDir");
            if (dir == null || dir.isBlank()) return;
            Path file = Path.of(dir, "progress.txt");
            Files.writeString(file, message + "\n");
        } catch (Exception ignored) {
            // Progress is best-effort for the GUI; probe success is independent.
        }
    }
}
