package com.aq.jvmsentinel.agent;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 轮询单进程的 LISTEN port，分类首个 HTTP 响应者并写入
 * {@code http-port.txt} / progress under the sandbox trace directory.
 *
 * <p>Args: {@code pid [traceDir]}</p>
 */
public final class WaitHttpReady {
    /** Dependency mock / common non-HTTP listeners — never treat as HTTP ready. */
    private static final Set<Integer> NON_HTTP_PORTS = Set.of(
            6379, 3306, 5432, 27017, 11211, 9200, 5672, 61616, 9092);

    private WaitHttpReady() { }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("pid and optional traceDir are required");
        }
        int pid = Integer.parseInt(args[0]);
        if (pid <= 0) throw new IllegalArgumentException("pid is invalid");
        Path traceDir = args.length == 2 && !args[1].isBlank()
                ? Path.of(args[1])
                : Path.of(System.getProperty("veyrion.sandbox.traceDir", "/tmp/veyrion-trace"));

        Set<Integer> ports = ProcessListenPorts.listenPorts(pid);
        String listen = ports.stream().map(String::valueOf).reduce((a, b) -> a + " " + b).orElse("");
        write(traceDir, "progress.txt",
                listen.isEmpty()
                        ? "进程 " + pid + " 暂无 LISTEN 端口"
                        : "进程 " + pid + " LISTEN 端口: " + listen);
        if (ports.isEmpty()) {
            System.exit(1);
            return;
        }
        List<Integer> ordered = new ArrayList<>();
        for (int port : ports) {
            if (!NON_HTTP_PORTS.contains(port)) ordered.add(port);
        }
        ordered.sort(Comparator
                .comparingInt((Integer port) -> httpPortRank(port))
                .thenComparingInt(Integer::intValue));
        if (ordered.isEmpty()) {
            write(traceDir, "progress.txt",
                    "进程 " + pid + " 仅有依赖替身/非 HTTP LISTEN 端口: " + listen);
            System.exit(2);
            return;
        }
        for (int port : ordered) {
            int status = probe(port, "/");
            if (status >= 0) {
                String contextPath = HttpContextPathDetector.detectFromApplicationLog(traceDir);
                if (contextPath.isEmpty()) {
                    contextPath = HttpContextPathDetector.normalize(
                            System.getProperty("veyrion.loopbackProbe.contextPath", ""));
                }
                HttpContextPathDetector.writeContextPathFile(traceDir, contextPath);
                int contextStatus = status;
                if (!contextPath.isEmpty()) {
                    int prefixed = probe(port, contextPath);
                    if (prefixed >= 0) {
                        contextStatus = prefixed;
                    }
                }
                write(traceDir, "http-port.txt", Integer.toString(port));
                write(traceDir, "listen-ports.txt", listen);
                write(traceDir, "progress.txt",
                        "进程 LISTEN 端口 " + port + " 判定为 HTTP（GET / → " + status
                                + (contextPath.isEmpty()
                                ? ""
                                : "；context-path " + contextPath + " → " + contextStatus)
                                + "；全部 LISTEN: " + listen + "）");
                System.out.println(port);
                return;
            }
        }
        System.exit(2);
    }

    private static int httpPortRank(int port) {
        return switch (port) {
            case 80, 8080, 8000, 8888, 8443 -> 0;
            default -> 10;
        };
    }

    /** Visible for acceptance checks: status line must be HTTP/1.x or HTTP/2. */
    static boolean isHttpStatusLine(String statusLine) {
        if (statusLine == null || statusLine.isBlank()) return false;
        String head = statusLine.trim().toUpperCase(Locale.ROOT);
        return head.startsWith("HTTP/1.") || head.startsWith("HTTP/2");
    }

    private static int probe(int port, String path) {
        String target = path == null || path.isBlank() ? "/" : path;
        if (!target.startsWith("/")) target = "/" + target;
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), 1_500);
            socket.setSoTimeout(1_500);
            OutputStream output = socket.getOutputStream();
            byte[] request = ("GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            output.write(request);
            output.flush();
            InputStream input = socket.getInputStream();
            byte[] buffer = new byte[128];
            int read = input.read(buffer);
            if (read <= 0) return -1;
            String head = new String(buffer, 0, read, StandardCharsets.ISO_8859_1);
            int lineEnd = head.indexOf("\r\n");
            if (lineEnd <= 0) return -1;
            String statusLine = head.substring(0, lineEnd).trim();
            if (!isHttpStatusLine(statusLine)) return -1;
            String[] parts = statusLine.split("\\s+");
            if (parts.length < 2) return -1;
            return Integer.parseInt(parts[1]);
        } catch (Exception ignored) {
            return -1;
        }
    }

    private static void write(Path directory, String name, String value) {
        try {
            Files.createDirectories(directory);
            Files.writeString(directory.resolve(name), value + "\n");
        } catch (Exception ignored) {
            // 尽力为 GUI 输出进度。
        }
    }
}
