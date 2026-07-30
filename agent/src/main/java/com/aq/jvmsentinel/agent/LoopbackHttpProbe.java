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
 * deny-all Docker 容器内使用的固定仅 loopback HTTP 刺激。
 *
 * <p>单条：{@code method route [port] [query]}。</p>
 * <p>批量：{@code --batch planFile port}；仍接受旧式 {@code @planFile port}。
 * 固定 {@code @planFile#port} 参数将 plan 与 port 保持在一个 shell token；
 * 单独 {@code @planFile} 回退到固定 property 或同级 {@code http-port.txt}。
 * 每行 plan 为
 * {@code METHOD\troute[\tquery[\ttrack[\tauthHeader[\tbladeAuthHeader[\texperimentPlanId[\tcookieHeader[\tlistenPort]]]]]]]]}。
 * {@code listenPort} 非空且 &gt;0 时覆盖批量默认 HTTP_PORT（executor/management 独立端口）。
 * 独立通道：Authorization、Blade-Auth 与 Cookie — 非空
 * {@code authHeader} 不隐含 {@code Blade-Auth} 或 Cookie，反之亦然。</p>
 *
 * <p>批量采用双阶段策略：快速并行 pass（800ms connect/read），
 * 再对 {@code BUSINESS_TIMEOUT} 目标有界慢重试（2000ms），
 * 优先 {@code UNAUTH}，以便恢复 AUTH_CHALLENGE / HTTP outcome，
 * 而不回退到完整顺序 2s 墙。</p>
 */
public final class LoopbackHttpProbe {
    private static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final int MAX_BATCH_LINES = 512;
    private static final int FAST_CONNECT_TIMEOUT_MS = 800;
    /** 略高于 800ms，使 FORCED 过 auth 后的 controller 工作较少被 defer 到 slow wave。 */
    private static final int FAST_READ_TIMEOUT_MS = 1500;
    private static final int SLOW_CONNECT_TIMEOUT_MS = 2000;
    private static final int SLOW_READ_TIMEOUT_MS = 2000;
    /** Wave-2 预算：恢复超时的高价值 / UNAUTH observation。 */
    private static final int MAX_SLOW_RETRIES = 128;
    private static final int DEFAULT_BATCH_THREADS = 8;
    private static final int MAX_BATCH_THREADS = 16;
    private static final byte[] SYNTHETIC_JSON_BODY =
            "{\"marker\":\"synthetic-http-entry-v1\"}".getBytes(StandardCharsets.US_ASCII);
    private static final String MULTIPART_BOUNDARY = "----veyrion-upload-boundary";
    /** probe-events.jsonl 内本地序号；worker 合并时重新编号。 */
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
        lastBatchContextPath = resolveContextPath(null);
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

    /** Plan 可选 listenPort；非法值 fail-closed 为 0（回退批量默认端口）。 */
    private static int parseOptionalListenPort(String value) {
        if (value == null || value.isBlank() || !value.matches("[0-9]{1,5}")) {
            return 0;
        }
        try {
            int port = Integer.parseInt(value);
            return port >= 1 && port <= 65_535 ? port : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    /**
     * 批量探测入口。返回进程风格退出码：0 成功，2 全部失败，3 零事件。
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
            if (parts.length < 2 || parts.length > 9) {
                throw new IllegalArgumentException("probe plan line is invalid");
            }
            ordinal++;
            int listenPort = 0;
            if (parts.length >= 9 && !parts[8].isBlank()) {
                listenPort = parseOptionalListenPort(parts[8].trim());
            }
            targets.add(new ProbeTarget(
                    parts[0].trim(),
                    parts[1].trim(),
                    parts.length >= 3 ? parts[2].trim() : "",
                    parts.length >= 4 && !parts[3].isBlank() ? parts[3].trim() : "UNAUTH",
                    parts.length >= 5 ? parts[4].trim() : "",
                    parts.length >= 6 ? parts[5].trim() : "",
                    parts.length >= 7 ? parts[6].trim() : "",
                    parts.length >= 8 ? parts[7].trim() : "",
                    listenPort,
                    ordinal));
        }
        if (targets.isEmpty()) throw new IllegalArgumentException("probe plan is empty");
        writtenEvents = 0;
        writeFailures = 0;
        lastBatchPort = port;
        lastBatchContextPath = resolveContextPath(planFile);
        if (!lastBatchContextPath.isEmpty()) {
            HttpContextPathDetector.writeContextPathFile(traceDirFor(planFile), lastBatchContextPath);
        }
        int concurrency = Math.min(targets.size(), batchConcurrency());
        writeProgress("批量探测启动：" + targets.size() + " 个目标，并发 " + concurrency
                + (lastBatchContextPath.isEmpty() ? "" : "，context-path " + lastBatchContextPath)
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
        // 证据写失败（常见于 trace tmpfs ENOSPC）不得伪装成功；否则 worker 会把缺尾部
        // 误判为 PROBE_EVENT_COVERAGE_INCOMPLETE。
        if (writeFailures > 0) {
            System.err.println("LoopbackHttpProbe event write failures=" + writeFailures
                    + " written=" + writtenEvents);
            return 4;
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
                int effectivePort = target.listenPort > 0 ? target.listenPort : port;
                return probeOne(target.method, target.route, effectivePort, target.query, target.track,
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
     * 优先 UNAUTH 超时（auth 区分），再其他 track；按序号稳定；硬上限。
     */
    static List<ProbeAttempt> selectSlowRetryTargets(List<ProbeAttempt> timedOut, int maxRetries) {
        if (timedOut == null || timedOut.isEmpty() || maxRetries <= 0) return List.of();
        List<ProbeAttempt> ranked = new ArrayList<>(timedOut);
        ranked.sort(Comparator
                .comparingInt((ProbeAttempt a) -> retryRank(a))
                .thenComparingInt(a -> a.target.ordinal));
        if (ranked.size() <= maxRetries) return List.copyOf(ranked);
        return List.copyOf(ranked.subList(0, maxRetries));
    }

    /**
     * FORCED_REACHABILITY 在 wire 上记为 ADMIN，但须在普通 COVERAGE
     * ADMIN 之前重试 — 否则 XSS METHOD_HOP 洪泛后 Shiro gate-pass PathTrace 会饿死。
     */
    static int retryRank(ProbeAttempt attempt) {
        if (attempt == null || attempt.target == null) {
            return 99;
        }
        String plan = attempt.target.experimentPlanId;
        if (plan != null && plan.toUpperCase(Locale.ROOT).contains("FORCED")) {
            return 0;
        }
        return trackRetryRank(attempt.target.track);
    }

    static int trackRetryRank(String track) {
        if (track == null) return 99;
        return switch (track) {
            case "UNAUTH" -> 1;
            case "USER" -> 2;
            case "ADMIN" -> 3;
            case "BYPASS_CANDIDATE" -> 4;
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
            String invalidTarget = route == null ? "" : route;
            return new ProbeAttempt(target, -1, "InvalidTarget",
                    invalidTarget, invalidTarget, connectTimeoutMs, readTimeoutMs, "");
        }
        boolean fileRead = looksFileReadDownload(target.route, target.query);
        boolean multipart = !fileRead && Set.of("POST", "PUT", "PATCH").contains(method)
                && looksMultipartUpload(target.route, target.query);
        boolean form = !multipart && Set.of("POST", "PUT", "PATCH").contains(method)
                && (fileRead || looksFormUrlEncoded(target.route, target.query));
        boolean xml = !multipart && !form && Set.of("POST", "PUT", "PATCH").contains(method)
                && looksXmlBody(target.route, target.query);
        // multipart/form：参数进 body；query 留空，避免绑定形态错位。
        // 读/下载：GET 保留 query；POST 走 form body 携带 path/file。
        // requestTarget 保持逻辑 MVC 路由（覆盖校验 / entry 对齐）；wire 另加 context-path。
        String requestTarget = multipart || form || target.query.isEmpty()
                ? target.route
                : target.route + "?" + ensureTraversalReadQuery(target.query, fileRead);
        String wireRequestTarget = HttpContextPathDetector.joinRequestTarget(
                lastBatchContextPath, requestTarget);
        byte[] body;
        String contentType;
        if (!Set.of("POST", "PUT", "PATCH").contains(method)) {
            body = new byte[0];
            contentType = "application/json";
        } else if (multipart) {
            body = buildMultipartBody(target.query);
            contentType = "multipart/form-data; boundary=" + MULTIPART_BOUNDARY;
        } else if (form) {
            body = buildFormUrlEncodedBody(
                    fileRead ? ensureTraversalReadQuery(target.query, true) : target.query);
            contentType = "application/x-www-form-urlencoded";
        } else if (xml) {
            body = buildSyntheticXmlBody(target.query);
            contentType = "application/xml";
        } else {
            body = SYNTHETIC_JSON_BODY;
            contentType = "application/json";
        }
        String correlationId = "req-" + target.ordinal + "-"
                + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        int status = -1;
        String error = "";
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            OutputStream output = socket.getOutputStream();
            String headerBlock = buildRequestHeaders(method, wireRequestTarget, body.length,
                    target.authHeader, target.bladeAuthHeader, correlationId,
                    target.track, target.experimentPlanId, target.cookieHeader, contentType);
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
        return new ProbeAttempt(target, status, error, requestTarget, wireRequestTarget,
                connectTimeoutMs, readTimeoutMs, correlationId);
    }

    /**
     * 构建 HTTP 请求头。Authorization 与 Blade-Auth 独立：
     * 任一通道不会从另一通道复制。
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
                correlationId, track, experimentPlanId, "", "application/json");
    }

    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader, String correlationId,
                                      String track, String experimentPlanId, String cookieHeader) {
        return buildRequestHeaders(method, requestTarget, contentLength, authHeader, bladeAuthHeader,
                correlationId, track, experimentPlanId, cookieHeader, "application/json");
    }

    static String buildRequestHeaders(String method, String requestTarget, int contentLength,
                                      String authHeader, String bladeAuthHeader, String correlationId,
                                      String track, String experimentPlanId, String cookieHeader,
                                      String contentType) {
        String type = contentType == null || contentType.isBlank() ? "application/json" : contentType;
        StringBuilder headers = new StringBuilder();
        headers.append(method).append(' ').append(requestTarget).append(" HTTP/1.1\r\n")
                .append("Host: 127.0.0.1\r\nConnection: close\r\n")
                .append("Content-Type: ").append(type).append("\r\n")
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

    /**
     * 上传类入口：JSON POST 无法绑定 {@code MultipartFile}，须发 multipart。
     * 路由含 upload/fileUpload，或 query 含 file=/multipartFile= 参数名。
     * 读/下载面优先 {@link #looksFileReadDownload}，避免被 multipart 抢走。
     */
    static boolean looksMultipartUpload(String route, String query) {
        if (looksFileReadDownload(route, query)) {
            return false;
        }
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("upload") || r.contains("multipart") || r.contains("fileupload")) {
            return true;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("file".equals(name) || "multipartfile".equals(name)
                    || name.endsWith("file") && name.contains("upload")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 任意文件读取 / 下载入口：路由含 download/read/getFile/file/view，
     * 或 query 含 path=/filepath=/filename=/name= 等读侧参数（非 multipart 上传）。
     */
    static boolean looksFileReadDownload(String route, String query) {
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("download") || r.contains("/read") || r.contains("readfile")
                || r.contains("getfile") || r.contains("file/get") || r.contains("/view/")
                || r.contains("preview") || r.endsWith("/file") || r.contains("/files/")) {
            // 明确上传路由除外
            if (r.contains("upload") || r.contains("multipart")) {
                return false;
            }
            return true;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        if (r.contains("upload") || r.contains("multipart")) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("path".equals(name) || "filepath".equals(name) || "filename".equals(name)
                    || "file_path".equals(name) || "dir".equals(name) || "directory".equals(name)
                    || "resource".equals(name) || "res".equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** 读侧探针：保证至少有一个穿越 path 样本，便于 FILE_READ 观测。 */
    static String ensureTraversalReadQuery(String query, boolean fileRead) {
        if (!fileRead) {
            return query == null ? "" : query;
        }
        String q = query == null ? "" : query.trim();
        if (q.isBlank()) {
            return "path=../veyrion-read.txt";
        }
        String lower = q.toLowerCase(Locale.ROOT);
        if (lower.contains("path=") || lower.contains("filepath=") || lower.contains("filename=")
                || lower.contains("file=") || lower.contains("name=") || lower.contains("dir=")) {
            return q;
        }
        return q + "&path=../veyrion-read.txt";
    }

    /**
     * Spring {@code @RequestParam} / form POST：JSON body 无法绑定，须发
     * {@code application/x-www-form-urlencoded}。
     * 路由含 login/save/submit/form，或 query 含典型表单字段且非 JDBC/JSON API。
     */
    static boolean looksFormUrlEncoded(String route, String query) {
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("login") || r.contains("signin") || r.contains("/form")
                || r.contains("submit") || r.endsWith("/save") || r.contains("/save/")
                || r.contains("urlencoded") || r.contains("doLogin")) {
            return true;
        }
        if (r.contains("json") || r.contains("graphql") || r.contains("api/v")) {
            return false;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        // JDBC test-connection 等保持 JSON+query（已有启发式样本）。
        if (q.contains("jdbcurl=") || q.contains("driverclass") || q.contains("driver=")) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("username".equals(name) || "password".equals(name) || "passwd".equals(name)
                    || "csrf".equals(name) || "token".equals(name) || "rememberme".equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** XXE / XML 入口：路由或参数名暗示 XML/SOAP。 */
    static boolean looksXmlBody(String route, String query) {
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("/xml") || r.contains("soap") || r.contains("xxe")
                || r.endsWith(".xml") || r.contains("/rss") || r.contains("atom")) {
            return true;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("xml".equals(name) || "payload".equals(name) && r.contains("xml")
                    || "document".equals(name) || "soap".equals(name)) {
                return true;
            }
        }
        return false;
    }

    static byte[] buildFormUrlEncodedBody(String query) {
        String q = query == null ? "" : query.trim();
        if (q.isBlank()) {
            q = "marker=synthetic-http-entry-v1";
        }
        return q.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] buildSyntheticXmlBody(String query) {
        String marker = "synthetic-http-entry-v1";
        if (query != null && !query.isBlank()) {
            for (String pair : query.split("&", -1)) {
                int eq = pair.indexOf('=');
                String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
                String value = eq < 0 ? "" : pair.substring(eq + 1).trim();
                if (("xml".equalsIgnoreCase(name) || "payload".equalsIgnoreCase(name)
                        || "document".equalsIgnoreCase(name)) && !value.isBlank()) {
                    marker = value;
                    break;
                }
            }
        }
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><veyrion marker=\""
                + marker + "\"/>";
        return xml.getBytes(StandardCharsets.US_ASCII);
    }

    /** 有界 multipart body：file 部件 + query 中其余字段。 */
    static byte[] buildMultipartBody(String query) {
        String filename = TRAVERSAL_UPLOAD_FILENAME;
        // 先扫 filename，避免 file= 部件先于 filename= 写出默认名。
        if (query != null && !query.isBlank()) {
            for (String pair : query.split("&", -1)) {
                int eq = pair.indexOf('=');
                String name = (eq < 0 ? pair : pair.substring(0, eq)).trim().toLowerCase(Locale.ROOT);
                String value = eq < 0 ? "" : pair.substring(eq + 1).trim();
                if (("filename".equals(name) || "originalfilename".equals(name)
                        || "filepath".equals(name) || "path".equals(name))
                        && !value.isBlank()
                        && value.matches("[A-Za-z0-9_./{}:-]{1,128}")) {
                    filename = value;
                    break;
                }
            }
        }
        StringBuilder body = new StringBuilder(256);
        boolean sawFile = false;
        if (query != null && !query.isBlank()) {
            for (String pair : query.split("&", -1)) {
                int eq = pair.indexOf('=');
                String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
                String value = eq < 0 ? "" : pair.substring(eq + 1).trim();
                if (name.isBlank()) continue;
                String lower = name.toLowerCase(Locale.ROOT);
                if ("filename".equals(lower) || "originalfilename".equals(lower)
                        || "filepath".equals(lower) || "path".equals(lower)) {
                    appendMultipartTextPart(body, name, value.isBlank() ? filename : value);
                    continue;
                }
                if ("file".equals(lower) || "multipartfile".equals(lower)) {
                    sawFile = true;
                    appendMultipartFilePart(body, name, filename);
                } else {
                    appendMultipartTextPart(body, name, value.isBlank() ? "synthetic" : value);
                }
            }
        }
        if (!sawFile) {
            appendMultipartFilePart(body, "file", filename);
        }
        body.append("--").append(MULTIPART_BOUNDARY).append("--\r\n");
        return body.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static final String TRAVERSAL_UPLOAD_FILENAME = "../veyrion-upload.bin";

    private static void appendMultipartFilePart(StringBuilder body, String name) {
        appendMultipartFilePart(body, name, TRAVERSAL_UPLOAD_FILENAME);
    }

    private static void appendMultipartFilePart(StringBuilder body, String name, String filename) {
        String safeName = filename == null || filename.isBlank()
                ? TRAVERSAL_UPLOAD_FILENAME : filename;
        body.append("--").append(MULTIPART_BOUNDARY).append("\r\n")
                .append("Content-Disposition: form-data; name=\"")
                .append(name).append("\"; filename=\"").append(safeName).append("\"\r\n")
                .append("Content-Type: application/octet-stream\r\n\r\n")
                .append("synthetic-upload-v1\r\n");
    }

    private static void appendMultipartTextPart(StringBuilder body, String name, String value) {
        body.append("--").append(MULTIPART_BOUNDARY).append("\r\n")
                .append("Content-Disposition: form-data; name=\"")
                .append(name).append("\"\r\n\r\n")
                .append(value).append("\r\n");
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
        String shownTarget = attempt.wireRequestTarget == null || attempt.wireRequestTarget.isBlank()
                ? attempt.requestTarget : attempt.wireRequestTarget;
        System.out.println(method + " " + shownTarget
                + " -> HTTP "
                + (attempt.status < 0 ? "UNKNOWN" : Integer.toString(attempt.status))
                + " (" + outcome + ", track=" + attempt.target.track
                + ", port " + lastBatchPort + ")"
                + (attempt.error.isEmpty() ? "" : "; " + attempt.error));
        writeProbeEvent(method, attempt.target.route, lastBatchPort, attempt.status,
                attempt.requestTarget, attempt.wireRequestTarget, attempt.error, outcome,
                attempt.target.track, attempt.correlationId, attempt.target.experimentPlanId);
    }

    /**
     * 探测侧 entry hit：HTTP 响应显示路由到达 app 或 auth 层时为 true
     * 层；缺失/不支持的方法为 false；传输失败时为 absent（{@code null}）。
     */
    static Boolean classifyEntryHit(int httpStatus) {
        if (httpStatus == 404 || httpStatus == 405) return Boolean.FALSE;
        if (httpStatus == 401 || httpStatus == 403) return Boolean.TRUE;
        if (httpStatus >= 200 && httpStatus < 400) return Boolean.TRUE;
        return null;
    }

    /**
     * 仅探测无法证明 binding 成功。仅对明确无路由情形 emit false。
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
                                                     String requestTarget, String wireRequestTarget,
                                                     String error, String outcomeClass,
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
            if (wireRequestTarget != null && !wireRequestTarget.isBlank()
                    && !wireRequestTarget.equals(requestTarget)) {
                detail.append(",\"wireRequestTarget\":\"")
                        .append(json(truncate(wireRequestTarget, 512))).append("\"");
            }
            if (lastBatchContextPath != null && !lastBatchContextPath.isBlank()) {
                detail.append(",\"contextPath\":\"")
                        .append(json(truncate(lastBatchContextPath, 128))).append("\"");
            }
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
    /** Servlet context path prefix for wire URIs; empty when root. */
    private static volatile String lastBatchContextPath = "";

    static String resolveContextPath(Path planFile) {
        Path traceDir = traceDirFor(planFile);
        return HttpContextPathDetector.resolve(traceDir);
    }

    static Path traceDirFor(Path planFile) {
        String configured = System.getProperty("veyrion.sandbox.traceDir");
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured);
        }
        if (planFile != null) {
            Path parent = planFile.toAbsolutePath().normalize().getParent();
            if (parent != null) return parent;
        }
        return Path.of(".");
    }

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
        /** 0 = 使用批量默认 HTTP_PORT。 */
        final int listenPort;
        final int ordinal;

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, int ordinal) {
            this(method, route, query, track, authHeader, "", "", "", 0, ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, int ordinal) {
            this(method, route, query, track, authHeader, bladeAuthHeader, "", "", 0, ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, String experimentPlanId, int ordinal) {
            this(method, route, query, track, authHeader, bladeAuthHeader, experimentPlanId, "", 0, ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, String experimentPlanId,
                    String cookieHeader, int ordinal) {
            this(method, route, query, track, authHeader, bladeAuthHeader, experimentPlanId,
                    cookieHeader, 0, ordinal);
        }

        ProbeTarget(String method, String route, String query, String track,
                    String authHeader, String bladeAuthHeader, String experimentPlanId,
                    String cookieHeader, int listenPort, int ordinal) {
            this.method = method;
            this.route = route;
            this.query = query;
            this.track = track;
            this.authHeader = authHeader == null ? "" : authHeader;
            this.bladeAuthHeader = bladeAuthHeader == null ? "" : bladeAuthHeader;
            this.experimentPlanId = experimentPlanId == null ? "" : experimentPlanId;
            this.cookieHeader = cookieHeader == null ? "" : cookieHeader;
            this.listenPort = listenPort < 0 || listenPort > 65_535 ? 0 : listenPort;
            this.ordinal = ordinal;
        }
    }

    static final class ProbeAttempt {
        final ProbeTarget target;
        final int status;
        final String error;
        /** 逻辑 MVC requestTarget（无 servlet context），供覆盖校验。 */
        final String requestTarget;
        /** 实际 HTTP 请求行 path（含 context-path）。 */
        final String wireRequestTarget;
        final int connectTimeoutMs;
        final int readTimeoutMs;
        final String correlationId;

        ProbeAttempt(ProbeTarget target, int status, String error, String requestTarget,
                     int connectTimeoutMs, int readTimeoutMs) {
            this(target, status, error, requestTarget, requestTarget, connectTimeoutMs, readTimeoutMs, "");
        }

        ProbeAttempt(ProbeTarget target, int status, String error, String requestTarget,
                     int connectTimeoutMs, int readTimeoutMs, String correlationId) {
            this(target, status, error, requestTarget, requestTarget,
                    connectTimeoutMs, readTimeoutMs, correlationId);
        }

        ProbeAttempt(ProbeTarget target, int status, String error, String requestTarget,
                     String wireRequestTarget, int connectTimeoutMs, int readTimeoutMs,
                     String correlationId) {
            this.target = target;
            this.status = status;
            this.error = error == null ? "" : error;
            this.requestTarget = requestTarget == null ? "" : requestTarget;
            this.wireRequestTarget = wireRequestTarget == null || wireRequestTarget.isBlank()
                    ? this.requestTarget : wireRequestTarget;
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
            this.correlationId = correlationId == null ? "" : correlationId;
        }

        boolean businessTimeout() {
            return status < 0 && error.contains("SocketTimeout");
        }
    }
}
