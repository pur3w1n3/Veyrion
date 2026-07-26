package com.aq.jvmsentinel.instrumentation.mock;

import com.aq.jvmsentinel.instrumentation.AgentRuntime;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded Redis RESP2/RESP3 substitute on loopback. It intentionally implements only the
 * startup/cache command subset listed in {@link #dispatch(List, Session)} and rejects every
 * unknown command. It is not a complete Redis implementation or a security boundary.
 */
public final class LoopbackRedisStub implements AutoCloseable {
    private static final int MAX_CLIENTS = 64;
    private static final int MAX_ARGUMENTS = 128;
    private static final int MAX_FRAME_BYTES = 1024 * 1024;
    private static final int MAX_LINE_BYTES = 4096;
    private static final int MAX_KEYS = 10_000;
    private static final long MAX_OPERATIONS = 100_000;

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong operations = new AtomicLong();
    private final Map<String, byte[]> strings = new ConcurrentHashMap<>();
    private final Map<String, Map<String, byte[]>> hashes = new ConcurrentHashMap<>();
    private final ServerSocket server;
    private final ExecutorService clients;
    private final Semaphore clientSlots = new Semaphore(MAX_CLIENTS);

    private LoopbackRedisStub(ServerSocket server) {
        this.server = server;
        this.clients = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "veyrion-redis-mock");
            thread.setDaemon(true);
            return thread;
        });
        clients.execute(this::acceptLoop);
        record("START", "RULE_GENERATED", "port=" + server.getLocalPort());
    }

    public static LoopbackRedisStub start(int port) throws IOException {
        ServerSocket socket = new ServerSocket(port, MAX_CLIENTS,
                InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        return new LoopbackRedisStub(socket);
    }

    public int port() {
        return server.getLocalPort();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = server.accept();
                if (!clientSlots.tryAcquire()) {
                    try (client) {
                        client.getOutputStream().write("-ERR mock client budget exhausted\r\n"
                                .getBytes(StandardCharsets.US_ASCII));
                    }
                    continue;
                }
                clients.execute(() -> handleClient(client));
            } catch (IOException closed) {
                if (running.get()) record("ACCEPT", "ERROR", closed.getClass().getSimpleName());
                return;
            }
        }
    }

    private void handleClient(Socket client) {
        try (Socket socket = client;
             InputStream input = socket.getInputStream();
             OutputStream output = socket.getOutputStream()) {
            socket.setSoTimeout(5_000);
            Session session = new Session();
            while (running.get() && !socket.isClosed()) {
                List<byte[]> command;
                try {
                    command = Resp.readCommand(input);
                } catch (SocketTimeoutException timeout) {
                    return;
                }
                if (command == null) return;
                long operation = operations.incrementAndGet();
                if (operation > MAX_OPERATIONS) {
                    Resp.writeError(output, "ERR mock operation budget exhausted");
                    output.flush();
                    record("BUDGET", "DENIED", "operation-limit");
                    return;
                }
                Reply reply = dispatch(command, session);
                reply.write(output, session.resp3);
                output.flush();
                if (reply.close) return;
            }
        } catch (IOException malformedOrClosed) {
            record("PROTOCOL", "DENIED", malformedOrClosed.getClass().getSimpleName());
        } finally {
            clientSlots.release();
        }
    }

    private Reply dispatch(List<byte[]> args, Session session) {
        if (args.isEmpty()) return denied("EMPTY", "empty-command");
        String name = text(args.get(0)).toUpperCase(Locale.ROOT);
        Reply reply;
        try {
            reply = switch (name) {
                case "HELLO" -> hello(args, session);
                case "PING" -> args.size() > 1 ? Reply.bulk(args.get(1)) : Reply.simple("PONG");
                case "ECHO" -> Reply.bulk(required(args, 1));
                case "AUTH", "SELECT" -> Reply.simple("OK");
                case "CLIENT" -> client(args);
                case "COMMAND" -> Reply.array(List.of());
                case "CONFIG" -> config(args);
                case "INFO" -> Reply.bulk("# Server\r\nredis_version:7.0.0-veyrion\r\n"
                        .getBytes(StandardCharsets.UTF_8));
                case "GET" -> Reply.bulkNullable(strings.get(key(required(args, 1))));
                case "SET" -> set(args);
                case "MGET" -> mget(args);
                case "MSET" -> mset(args);
                case "DEL", "UNLINK" -> delete(args);
                case "EXISTS" -> exists(args);
                case "TYPE" -> type(args);
                case "TTL", "PTTL" -> Reply.integer(existsKey(key(required(args, 1))) ? -1 : -2);
                case "EXPIRE", "PEXPIRE", "PERSIST" ->
                        Reply.integer(existsKey(key(required(args, 1))) ? 1 : 0);
                case "HGET" -> hget(args);
                case "HSET" -> hset(args);
                case "HMGET" -> hmget(args);
                case "HGETALL" -> hgetall(args);
                case "INCR" -> increment(args);
                case "DBSIZE" -> Reply.integer(strings.size() + hashes.size());
                case "FLUSHDB", "FLUSHALL" -> flush();
                case "QUIT" -> Reply.close("OK");
                default -> denied(name, "unknown-command");
            };
        } catch (IllegalArgumentException invalid) {
            reply = denied(name, "invalid-arguments");
        }
        if (!reply.denied) record(name, "RULE_GENERATED", reply.summary);
        return reply;
    }

    private Reply hello(List<byte[]> args, Session session) {
        if (args.size() > 1) {
            String version = text(args.get(1));
            if (!version.equals("2") && !version.equals("3")) {
                return denied("HELLO", "unsupported-protocol-version");
            }
            session.resp3 = version.equals("3");
        }
        Map<String, Reply> fields = new LinkedHashMap<>();
        fields.put("server", Reply.bulk("redis".getBytes(StandardCharsets.UTF_8)));
        fields.put("version", Reply.bulk("7.0.0-veyrion".getBytes(StandardCharsets.UTF_8)));
        fields.put("proto", Reply.integer(session.resp3 ? 3 : 2));
        fields.put("id", Reply.integer(1));
        fields.put("mode", Reply.bulk("standalone".getBytes(StandardCharsets.UTF_8)));
        fields.put("role", Reply.bulk("master".getBytes(StandardCharsets.UTF_8)));
        return Reply.map(fields);
    }

    private Reply client(List<byte[]> args) {
        String operation = args.size() > 1 ? text(args.get(1)).toUpperCase(Locale.ROOT) : "";
        return switch (operation) {
            case "SETNAME", "SETINFO", "TRACKING", "CACHING" -> Reply.simple("OK");
            case "GETNAME" -> Reply.nullBulk();
            case "ID" -> Reply.integer(1);
            default -> denied("CLIENT", "unsupported-subcommand");
        };
    }

    private Reply config(List<byte[]> args) {
        String operation = args.size() > 1 ? text(args.get(1)).toUpperCase(Locale.ROOT) : "";
        if (operation.equals("GET")) return Reply.array(List.of());
        if (operation.equals("SET")) return Reply.simple("OK");
        return denied("CONFIG", "unsupported-subcommand");
    }

    private Reply set(List<byte[]> args) {
        String key = key(required(args, 1));
        byte[] value = value(required(args, 2));
        ensureCapacity(key);
        strings.put(key, value.clone());
        hashes.remove(key);
        return Reply.simple("OK");
    }

    private Reply mget(List<byte[]> args) {
        requireSize(args, 2, MAX_ARGUMENTS);
        List<Reply> values = new ArrayList<>();
        for (int i = 1; i < args.size(); i++) values.add(Reply.bulkNullable(strings.get(key(args.get(i)))));
        return Reply.array(values);
    }

    private Reply mset(List<byte[]> args) {
        if (args.size() < 3 || args.size() % 2 == 0) throw new IllegalArgumentException();
        for (int i = 1; i < args.size(); i += 2) {
            String key = key(args.get(i));
            ensureCapacity(key);
            strings.put(key, value(args.get(i + 1)).clone());
            hashes.remove(key);
        }
        return Reply.simple("OK");
    }

    private Reply delete(List<byte[]> args) {
        requireSize(args, 2, MAX_ARGUMENTS);
        long removed = 0;
        for (int i = 1; i < args.size(); i++) {
            String key = key(args.get(i));
            if (strings.remove(key) != null) removed++;
            if (hashes.remove(key) != null) removed++;
        }
        return Reply.integer(removed);
    }

    private Reply exists(List<byte[]> args) {
        requireSize(args, 2, MAX_ARGUMENTS);
        long found = 0;
        for (int i = 1; i < args.size(); i++) if (existsKey(key(args.get(i)))) found++;
        return Reply.integer(found);
    }

    private Reply type(List<byte[]> args) {
        String key = key(required(args, 1));
        return Reply.simple(strings.containsKey(key) ? "string" : hashes.containsKey(key) ? "hash" : "none");
    }

    private Reply hget(List<byte[]> args) {
        Map<String, byte[]> hash = hashes.get(key(required(args, 1)));
        return Reply.bulkNullable(hash == null ? null : hash.get(key(required(args, 2))));
    }

    private Reply hset(List<byte[]> args) {
        if (args.size() < 4 || args.size() % 2 != 0) throw new IllegalArgumentException();
        String key = key(args.get(1));
        ensureCapacity(key);
        strings.remove(key);
        Map<String, byte[]> hash = hashes.computeIfAbsent(key, ignored -> new ConcurrentHashMap<>());
        long added = 0;
        for (int i = 2; i < args.size(); i += 2) {
            if (hash.put(key(args.get(i)), value(args.get(i + 1)).clone()) == null) added++;
        }
        return Reply.integer(added);
    }

    private Reply hmget(List<byte[]> args) {
        requireSize(args, 3, MAX_ARGUMENTS);
        Map<String, byte[]> hash = hashes.get(key(args.get(1)));
        List<Reply> values = new ArrayList<>();
        for (int i = 2; i < args.size(); i++) {
            values.add(Reply.bulkNullable(hash == null ? null : hash.get(key(args.get(i)))));
        }
        return Reply.array(values);
    }

    private Reply hgetall(List<byte[]> args) {
        Map<String, byte[]> hash = hashes.get(key(required(args, 1)));
        if (hash == null) return Reply.array(List.of());
        List<Reply> values = new ArrayList<>();
        hash.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            values.add(Reply.bulk(entry.getKey().getBytes(StandardCharsets.UTF_8)));
            values.add(Reply.bulk(entry.getValue()));
        });
        return Reply.array(values);
    }

    private Reply increment(List<byte[]> args) {
        String key = key(required(args, 1));
        long current = strings.containsKey(key) ? Long.parseLong(text(strings.get(key))) : 0;
        long next = Math.addExact(current, 1);
        ensureCapacity(key);
        strings.put(key, Long.toString(next).getBytes(StandardCharsets.US_ASCII));
        return Reply.integer(next);
    }

    private Reply flush() {
        strings.clear();
        hashes.clear();
        return Reply.simple("OK");
    }

    private Reply denied(String operation, String reason) {
        record(operation, "DENIED", reason);
        return Reply.error("ERR " + reason, true);
    }

    private void ensureCapacity(String key) {
        if (!existsKey(key) && strings.size() + hashes.size() >= MAX_KEYS) {
            throw new IllegalArgumentException("key budget exhausted");
        }
    }

    private boolean existsKey(String key) {
        return strings.containsKey(key) || hashes.containsKey(key);
    }

    private static byte[] required(List<byte[]> args, int index) {
        if (args.size() != index + 1 && index >= args.size()) throw new IllegalArgumentException();
        return args.get(index);
    }

    private static void requireSize(List<byte[]> args, int minimum, int maximum) {
        if (args.size() < minimum || args.size() > maximum) throw new IllegalArgumentException();
    }

    private static String key(byte[] value) {
        if (value.length == 0 || value.length > 1024) throw new IllegalArgumentException();
        return text(value);
    }

    private static byte[] value(byte[] value) {
        if (value.length > MAX_FRAME_BYTES) throw new IllegalArgumentException();
        return value;
    }

    private static String text(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static void record(String operation, String outcome, String summary) {
        AgentRuntime.recordJdbc(LoopbackRedisStub.class.getName(), "resp",
                Map.of("captureMode", "DEPENDENCY_PROTOCOL_MOCK",
                        "dependencyMode", "MOCK",
                        "provenance", "RULE_GENERATED",
                        "protocol", "REDIS_RESP",
                        "operation", operation,
                        "outcome", outcome,
                        "summary", summary));
    }

    @Override
    public void close() {
        running.set(false);
        try {
            server.close();
        } catch (IOException ignored) {
        }
        clients.shutdownNow();
    }

    private static final class Session {
        private boolean resp3;
    }

    private static final class Reply {
        private enum Type { SIMPLE, ERROR, INTEGER, BULK, ARRAY, MAP, NULL }

        private final Type type;
        private final Object value;
        private final boolean denied;
        private final boolean close;
        private final String summary;

        private Reply(Type type, Object value, boolean denied, boolean close, String summary) {
            this.type = type;
            this.value = value;
            this.denied = denied;
            this.close = close;
            this.summary = summary;
        }

        static Reply simple(String value) { return new Reply(Type.SIMPLE, value, false, false, "simple"); }
        static Reply error(String value, boolean denied) { return new Reply(Type.ERROR, value, denied, false, "error"); }
        static Reply integer(long value) { return new Reply(Type.INTEGER, value, false, false, "integer"); }
        static Reply bulk(byte[] value) { return new Reply(Type.BULK, value.clone(), false, false, "bulk-bytes=" + value.length); }
        static Reply bulkNullable(byte[] value) { return value == null ? nullBulk() : bulk(value); }
        static Reply nullBulk() { return new Reply(Type.NULL, null, false, false, "null"); }
        static Reply array(List<Reply> value) { return new Reply(Type.ARRAY, List.copyOf(value), false, false, "array-size=" + value.size()); }
        static Reply map(Map<String, Reply> value) { return new Reply(Type.MAP, Map.copyOf(value), false, false, "map-size=" + value.size()); }
        static Reply close(String value) { return new Reply(Type.SIMPLE, value, false, true, "close"); }

        @SuppressWarnings("unchecked")
        void write(OutputStream output, boolean resp3) throws IOException {
            switch (type) {
                case SIMPLE -> output.write(("+" + value + "\r\n").getBytes(StandardCharsets.UTF_8));
                case ERROR -> Resp.writeError(output, String.valueOf(value));
                case INTEGER -> output.write((":" + value + "\r\n").getBytes(StandardCharsets.US_ASCII));
                case BULK -> Resp.writeBulk(output, (byte[]) value);
                case NULL -> output.write((resp3 ? "_\r\n" : "$-1\r\n").getBytes(StandardCharsets.US_ASCII));
                case ARRAY -> {
                    List<Reply> replies = (List<Reply>) value;
                    output.write(("*" + replies.size() + "\r\n").getBytes(StandardCharsets.US_ASCII));
                    for (Reply reply : replies) reply.write(output, resp3);
                }
                case MAP -> {
                    Map<String, Reply> fields = (Map<String, Reply>) value;
                    if (resp3) {
                        output.write(("%" + fields.size() + "\r\n").getBytes(StandardCharsets.US_ASCII));
                    } else {
                        output.write(("*" + (fields.size() * 2) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                    }
                    for (Map.Entry<String, Reply> entry : fields.entrySet()) {
                        Resp.writeBulk(output, entry.getKey().getBytes(StandardCharsets.UTF_8));
                        entry.getValue().write(output, resp3);
                    }
                }
            }
        }
    }

    private static final class Resp {
        private Resp() { }

        static List<byte[]> readCommand(InputStream input) throws IOException {
            int type = input.read();
            if (type < 0) return null;
            if (type != '*') throw new IOException("commands must be RESP arrays");
            int count = number(readLine(input));
            if (count <= 0 || count > MAX_ARGUMENTS) throw new IOException("invalid argument count");
            List<byte[]> args = new ArrayList<>(count);
            int charged = 0;
            for (int i = 0; i < count; i++) {
                int itemType = input.read();
                byte[] value;
                if (itemType == '$' || itemType == '=' || itemType == '!') {
                    int length = number(readLine(input));
                    if (length < 0 || length > MAX_FRAME_BYTES || charged > MAX_FRAME_BYTES - length) {
                        throw new IOException("RESP frame exceeds limit");
                    }
                    value = input.readNBytes(length);
                    if (value.length != length || input.read() != '\r' || input.read() != '\n') {
                        throw new EOFException("malformed RESP bulk string");
                    }
                } else if (itemType == '+' || itemType == ':' || itemType == '#') {
                    value = readLine(input).getBytes(StandardCharsets.UTF_8);
                } else {
                    throw new IOException("unsupported RESP command item");
                }
                charged += value.length;
                args.add(value);
            }
            return args;
        }

        static void writeBulk(OutputStream output, byte[] value) throws IOException {
            output.write(("$" + value.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            output.write(value);
            output.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        }

        static void writeError(OutputStream output, String value) throws IOException {
            output.write(("-" + value + "\r\n").getBytes(StandardCharsets.UTF_8));
        }

        private static String readLine(InputStream input) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int previous = -1;
            while (buffer.size() <= MAX_LINE_BYTES) {
                int current = input.read();
                if (current < 0) throw new EOFException("unexpected end of RESP stream");
                if (previous == '\r' && current == '\n') {
                    byte[] bytes = buffer.toByteArray();
                    return new String(bytes, 0, bytes.length - 1, StandardCharsets.US_ASCII);
                }
                buffer.write(current);
                previous = current;
            }
            throw new IOException("RESP line exceeds limit");
        }

        private static int number(String value) throws IOException {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException invalid) {
                throw new IOException("invalid RESP number", invalid);
            }
        }
    }
}
