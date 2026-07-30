package com.aq.jvmsentinel.agent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 通过关联 {@code /proc/<pid>/fd}
 * socket inode 与 {@code /proc/net/tcp{,6}} LISTEN 行，列出单进程拥有的 TCP 监听端口。
 *
 * <p>用于 deny-all Docker 沙箱内，而非猜测常见 HTTP 端口。</p>
 */
public final class ProcessListenPorts {
    private static final Pattern SOCKET_INODE = Pattern.compile("socket:\\[(\\d+)]");
    /** Linux TCP state 0A = LISTEN。 */
    private static final String LISTEN_STATE = "0A";

    private ProcessListenPorts() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("pid is required");
        long pid = Long.parseLong(args[0]);
        if (pid <= 0 || pid > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("pid is invalid");
        }
        Set<Integer> ports = listenPorts((int) pid);
        System.out.println(ports.stream().map(String::valueOf).collect(Collectors.joining(" ")));
    }

    static Set<Integer> listenPorts(int pid) throws IOException {
        Path proc = Path.of("/proc", Integer.toString(pid));
        if (!Files.isDirectory(proc, LinkOption.NOFOLLOW_LINKS)) {
            return Set.of();
        }
        Set<String> inodes = socketInodes(proc.resolve("fd"));
        if (inodes.isEmpty()) return Set.of();
        Set<Integer> ports = new LinkedHashSet<>();
        collectListenPorts(Path.of("/proc/net/tcp"), inodes, ports);
        collectListenPorts(Path.of("/proc/net/tcp6"), inodes, ports);
        // 存在时优先进程本地 net 表（通常同 mount namespace）。
        collectListenPorts(proc.resolve("net/tcp"), inodes, ports);
        collectListenPorts(proc.resolve("net/tcp6"), inodes, ports);
        return ports;
    }

    private static Set<String> socketInodes(Path fdDirectory) throws IOException {
        Set<String> inodes = new LinkedHashSet<>();
        if (!Files.isDirectory(fdDirectory, LinkOption.NOFOLLOW_LINKS)) return inodes;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(fdDirectory)) {
            for (Path entry : stream) {
                try {
                    Path target = Files.readSymbolicLink(entry);
                    Matcher matcher = SOCKET_INODE.matcher(target.toString());
                    if (matcher.matches()) inodes.add(matcher.group(1));
                } catch (IOException | SecurityException ignored) {
                    // 跳过不可读 descriptor。
                }
            }
        }
        return inodes;
    }

    private static void collectListenPorts(Path table, Set<String> inodes, Set<Integer> ports)
            throws IOException {
        if (!Files.isRegularFile(table, LinkOption.NOFOLLOW_LINKS)) return;
        try (BufferedReader reader = Files.newBufferedReader(table, StandardCharsets.US_ASCII)) {
            String header = reader.readLine();
            if (header == null) return;
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.trim().split("\\s+");
                // /proc/net/tcp 列：local_address remote_address st ... inode
                if (columns.length < 10) continue;
                if (!LISTEN_STATE.equalsIgnoreCase(columns[3])) continue;
                String inode = columns[9];
                if (!inodes.contains(inode)) continue;
                int port = parseHexPort(columns[1]);
                if (port > 0 && port <= 65535) ports.add(port);
            }
        }
    }

    private static int parseHexPort(String localAddress) {
        int colon = localAddress.lastIndexOf(':');
        if (colon < 0 || colon == localAddress.length() - 1) return -1;
        try {
            return Integer.parseInt(localAddress.substring(colon + 1), 16);
        } catch (NumberFormatException invalid) {
            return -1;
        }
    }
}
