package com.aq.jvmsentinel.instrumentation.mock;

import com.aq.jvmsentinel.instrumentation.AgentRuntime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Minimal RESP server on loopback only. Enough for Spring Data Redis / Lettuce PING/GET/SET
 * during deny-all sandbox boot. Not a real Redis and not a security boundary.
 */
public final class LoopbackRedisStub implements AutoCloseable {
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Map<String, byte[]> store = new ConcurrentHashMap<>();
    private final ServerSocket server;
    private final ExecutorService acceptors;

    private LoopbackRedisStub(ServerSocket server) {
        this.server = server;
        this.acceptors = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "veyrion-redis-mock");
            thread.setDaemon(true);
            return thread;
        });
        acceptors.execute(this::acceptLoop);
        AgentRuntime.recordJdbc(getClass().getName(), "redisStubStart",
                Map.of("captureMode", "DEPENDENCY_MOCK",
                        "dependencyMode", "MOCK",
                        "provenance", "RULE_GENERATED",
                        "port", Integer.toString(server.getLocalPort())));
    }

    public static LoopbackRedisStub start(int port) throws IOException {
        ServerSocket socket = new ServerSocket(port, 50, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        return new LoopbackRedisStub(socket);
    }

    public int port() {
        return server.getLocalPort();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = server.accept();
                acceptors.execute(() -> handleClient(client));
            } catch (IOException closed) {
                if (running.get()) {
                    AgentRuntime.recordJdbc(getClass().getName(), "redisAcceptError",
                            Map.of("captureMode", "DEPENDENCY_MOCK", "error", closed.getClass().getSimpleName()));
                }
                return;
            }
        }
    }

    private void handleClient(Socket client) {
        try (Socket socket = client;
             InputStream input = socket.getInputStream();
             OutputStream output = socket.getOutputStream()) {
            while (running.get() && !socket.isClosed()) {
                Object command = Resp.read(input);
                if (command == null) return;
                writeReply(output, dispatch(command));
                output.flush();
            }
        } catch (IOException ignored) {
        }
    }

    private Object dispatch(Object command) {
        if (!(command instanceof Object[] args) || args.length == 0) {
            return error("ERR empty command");
        }
        String name = string(args[0]).toUpperCase();
        return switch (name) {
            case "PING" -> args.length > 1 ? string(args[1]).getBytes(StandardCharsets.UTF_8) : "PONG";
            case "ECHO" -> args.length > 1 ? string(args[1]).getBytes(StandardCharsets.UTF_8) : "".getBytes(StandardCharsets.UTF_8);
            case "AUTH", "SELECT", "CLIENT", "CONFIG", "COMMAND", "INFO", "CLUSTER" -> "OK";
            case "GET" -> args.length > 1 ? store.get(string(args[1])) : null;
            case "SET" -> {
                if (args.length > 2) store.put(string(args[1]), bytes(args[2]));
                yield "OK";
            }
            case "DEL" -> {
                int removed = 0;
                for (int i = 1; i < args.length; i++) {
                    if (store.remove(string(args[i])) != null) removed++;
                }
                yield removed;
            }
            case "EXISTS" -> {
                int found = 0;
                for (int i = 1; i < args.length; i++) {
                    if (store.containsKey(string(args[i]))) found++;
                }
                yield found;
            }
            case "DBSIZE" -> store.size();
            case "FLUSHDB", "FLUSHALL" -> {
                store.clear();
                yield "OK";
            }
            case "QUIT" -> "OK";
            default -> "OK";
        };
    }

    private static void writeReply(OutputStream output, Object value) throws IOException {
        if (value == null) {
            output.write("$-1\r\n".getBytes(StandardCharsets.US_ASCII));
        } else if (value instanceof String text) {
            output.write(('+' + text + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else if (value instanceof Integer number) {
            output.write((':' + number + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else if (value instanceof Long number) {
            output.write((':' + number + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else if (value instanceof byte[] bulk) {
            output.write(('$'+ bulk.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            output.write(bulk);
            output.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        } else if (value instanceof Object[] error && error.length == 1 && error[0] instanceof String message
                && message.startsWith("ERR")) {
            output.write(('-' + message + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else {
            output.write("+OK\r\n".getBytes(StandardCharsets.US_ASCII));
        }
    }

    private static Object error(String message) {
        return new Object[]{message};
    }

    private static String string(Object value) {
        if (value instanceof byte[] bytes) return new String(bytes, StandardCharsets.UTF_8);
        return String.valueOf(value);
    }

    private static byte[] bytes(Object value) {
        if (value instanceof byte[] bytes) return bytes;
        return string(value).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void close() {
        running.set(false);
        try {
            server.close();
        } catch (IOException ignored) {
        }
        acceptors.shutdownNow();
    }

    /** Tiny RESP array/bulk reader. */
    private static final class Resp {
        private Resp() {
        }

        static Object read(InputStream input) throws IOException {
            int type = input.read();
            if (type < 0) return null;
            return switch (type) {
                case '*' -> {
                    int count = Integer.parseInt(readLine(input));
                    if (count < 0) yield null;
                    Object[] values = new Object[count];
                    for (int i = 0; i < count; i++) values[i] = read(input);
                    yield values;
                }
                case '$' -> {
                    int length = Integer.parseInt(readLine(input));
                    if (length < 0) yield null;
                    byte[] buffer = input.readNBytes(length);
                    if (input.read() != '\r' || input.read() != '\n') {
                        throw new IOException("malformed bulk string trailer");
                    }
                    yield buffer;
                }
                case '+' , '-', ':' -> readLine(input);
                default -> throw new IOException("unsupported RESP type");
            };
        }

        private static String readLine(InputStream input) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int previous = -1;
            int current;
            while ((current = input.read()) >= 0) {
                if (previous == '\r' && current == '\n') {
                    byte[] bytes = buffer.toByteArray();
                    return new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.UTF_8);
                }
                buffer.write(current);
                previous = current;
            }
            throw new IOException("unexpected end of RESP stream");
        }
    }
}
