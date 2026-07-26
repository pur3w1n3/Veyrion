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
import java.util.Set;

/**
 * Polls one process for LISTEN ports, classifies the first HTTP responder, and writes
 * {@code http-port.txt} / progress under the sandbox trace directory.
 *
 * <p>Args: {@code pid [traceDir]}</p>
 */
public final class WaitHttpReady {
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
        // Prefer common HTTP listen ports ahead of Redis/DB stubs (e.g. 6379).
        List<Integer> ordered = new ArrayList<>(ports);
        ordered.sort(Comparator
                .comparingInt((Integer port) -> httpPortRank(port))
                .thenComparingInt(Integer::intValue));
        for (int port : ordered) {
            int status = probe(port);
            if (status >= 0) {
                write(traceDir, "http-port.txt", Integer.toString(port));
                write(traceDir, "listen-ports.txt", listen);
                write(traceDir, "progress.txt",
                        "进程 LISTEN 端口 " + port + " 判定为 HTTP（GET / → " + status
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
            case 6379, 3306, 5432, 27017, 11211 -> 100;
            default -> 10;
        };
    }

    private static int probe(int port) {
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), 1_500);
            socket.setSoTimeout(1_500);
            OutputStream output = socket.getOutputStream();
            byte[] request = ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
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
            String[] parts = head.substring(0, lineEnd).trim().split("\\s+");
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
            // Best-effort progress for the GUI.
        }
    }
}
