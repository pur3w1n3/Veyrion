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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded MySQL classic-protocol substitute for driver startup and harmless query progression.
 * Supported commands are handshake/auth, COM_QUERY, COM_STMT_PREPARE/EXECUTE/CLOSE, ping and quit.
 * It neither implements SQL semantics nor represents a real MySQL server.
 */
public final class LoopbackMysqlStub implements AutoCloseable {
    private static final int MAX_CLIENTS = 64;
    private static final int MAX_PACKET_BYTES = 1024 * 1024;
    private static final int MAX_PREPARED_PER_CLIENT = 256;
    private static final long MAX_OPERATIONS = 100_000;

    private static final int CLIENT_LONG_PASSWORD = 0x00000001;
    private static final int CLIENT_CONNECT_WITH_DB = 0x00000008;
    private static final int CLIENT_PROTOCOL_41 = 0x00000200;
    private static final int CLIENT_TRANSACTIONS = 0x00002000;
    private static final int CLIENT_SECURE_CONNECTION = 0x00008000;
    private static final int CLIENT_MULTI_RESULTS = 0x00020000;
    private static final int CLIENT_PLUGIN_AUTH = 0x00080000;
    private static final int CLIENT_CONNECT_ATTRS = 0x00100000;
    private static final int CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;
    private static final int CAPABILITIES = CLIENT_LONG_PASSWORD | CLIENT_CONNECT_WITH_DB
            | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION
            | CLIENT_MULTI_RESULTS | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS
            | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong operations = new AtomicLong();
    private final AtomicInteger connectionIds = new AtomicInteger(1000);
    private final ServerSocket server;
    private final ExecutorService clients;
    private final Semaphore clientSlots = new Semaphore(MAX_CLIENTS);

    private LoopbackMysqlStub(ServerSocket server) {
        this.server = server;
        this.clients = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "veyrion-mysql-mock");
            thread.setDaemon(true);
            return thread;
        });
        clients.execute(this::acceptLoop);
        record("START", "RULE_GENERATED", "port=" + server.getLocalPort());
    }

    public static LoopbackMysqlStub start(int port) throws IOException {
        ServerSocket socket = new ServerSocket(port, MAX_CLIENTS,
                InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        return new LoopbackMysqlStub(socket);
    }

    public int port() {
        return server.getLocalPort();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = server.accept();
                if (!clientSlots.tryAcquire()) {
                    client.close();
                    record("CONNECT", "DENIED", "client-budget");
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
            writePacket(output, 0, handshake(connectionIds.incrementAndGet()));
            Packet login = readPacket(input);
            if (login == null || login.payload.length < 32) throw new IOException("short login packet");
            session.clientCapabilities = littleInt(login.payload, 0);
            if ((session.clientCapabilities & CLIENT_PROTOCOL_41) == 0) {
                writePacket(output, login.sequence + 1, error(1047, "08S01", "protocol 4.1 required"));
                record("AUTH", "DENIED", "protocol-41-required");
                return;
            }
            writePacket(output, login.sequence + 1, ok());
            record("AUTH", "RULE_GENERATED", "accepted-without-credential-capture");

            while (running.get() && !socket.isClosed()) {
                Packet packet;
                try {
                    packet = readPacket(input);
                } catch (SocketTimeoutException timeout) {
                    return;
                }
                if (packet == null) return;
                if (operations.incrementAndGet() > MAX_OPERATIONS) {
                    writePacket(output, 1, error(1226, "42000", "mock operation budget exhausted"));
                    record("BUDGET", "DENIED", "operation-limit");
                    return;
                }
                if (!dispatch(packet.payload, output, session)) return;
            }
        } catch (IOException malformedOrClosed) {
            record("PROTOCOL", "DENIED", malformedOrClosed.getClass().getSimpleName());
        } finally {
            clientSlots.release();
        }
    }

    private boolean dispatch(byte[] payload, OutputStream output, Session session) throws IOException {
        if (payload.length == 0) {
            denyCommand(output, "EMPTY", "empty-command");
            return true;
        }
        int command = payload[0] & 0xff;
        switch (command) {
            case 0x01 -> {
                record("COM_QUIT", "RULE_GENERATED", "closed");
                return false;
            }
            case 0x02 -> {
                writePacket(output, 1, ok());
                record("COM_INIT_DB", "RULE_GENERATED", "accepted");
            }
            case 0x03 -> query(Arrays.copyOfRange(payload, 1, payload.length), output, "COM_QUERY");
            case 0x0e -> {
                writePacket(output, 1, ok());
                record("COM_PING", "RULE_GENERATED", "ok");
            }
            case 0x16 -> prepare(Arrays.copyOfRange(payload, 1, payload.length), output, session);
            case 0x17 -> execute(payload, output, session);
            case 0x19 -> closeStatement(payload, session);
            case 0x1a -> resetStatement(payload, output, session);
            default -> denyCommand(output, "COMMAND_" + command, "unsupported-command");
        }
        return true;
    }

    private void query(byte[] sqlBytes, OutputStream output, String operation) throws IOException {
        if (sqlBytes.length == 0 || sqlBytes.length > MAX_PACKET_BYTES) {
            denyCommand(output, operation, "invalid-query");
            return;
        }
        String sql = new String(sqlBytes, StandardCharsets.UTF_8).trim();
        String keyword = firstKeyword(sql);
        switch (keyword) {
            case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN" -> oneColumnResult(output, syntheticValue(sql));
            case "SET", "USE", "BEGIN", "START", "COMMIT", "ROLLBACK", "INSERT", "UPDATE",
                    "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE" -> writePacket(output, 1, ok());
            default -> {
                denyCommand(output, operation, "unsupported-sql-class");
                return;
            }
        }
        recordStatement(operation, "RULE_GENERATED", keyword, sql, sql.contains("?"));
    }

    private void prepare(byte[] sql, OutputStream output, Session session) throws IOException {
        if (sql.length == 0 || session.prepared.size() >= MAX_PREPARED_PER_CLIENT) {
            denyCommand(output, "COM_STMT_PREPARE", "statement-budget-or-empty");
            return;
        }
        int id = session.nextStatementId++;
        session.prepared.put(id, sql.clone());
        int parameters = 0;
        for (byte value : sql) if (value == '?') parameters++;
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        response.write(0x00);
        little(response, id, 4);
        little(response, 0, 2);
        little(response, parameters, 2);
        response.write(0x00);
        little(response, 0, 2);
        writePacket(output, 1, response.toByteArray());
        int sequence = 2;
        for (int index = 0; index < parameters; index++) {
            writePacket(output, sequence++, columnDefinition("?" + (index + 1)));
        }
        if (parameters > 0) writePacket(output, sequence, eof());
        String text = new String(sql, StandardCharsets.UTF_8);
        recordStatement("COM_STMT_PREPARE", "RULE_GENERATED", firstKeyword(text), text, parameters > 0);
    }

    private void execute(byte[] payload, OutputStream output, Session session) throws IOException {
        if (payload.length < 10) {
            denyCommand(output, "COM_STMT_EXECUTE", "short-packet");
            return;
        }
        int id = littleInt(payload, 1);
        byte[] sql = session.prepared.get(id);
        if (sql == null) {
            denyCommand(output, "COM_STMT_EXECUTE", "unknown-statement");
            return;
        }
        query(sql, output, "COM_STMT_EXECUTE");
    }

    private void closeStatement(byte[] payload, Session session) {
        if (payload.length >= 5) session.prepared.remove(littleInt(payload, 1));
        record("COM_STMT_CLOSE", "RULE_GENERATED", "closed");
    }

    private void resetStatement(byte[] payload, OutputStream output, Session session) throws IOException {
        if (payload.length < 5 || !session.prepared.containsKey(littleInt(payload, 1))) {
            denyCommand(output, "COM_STMT_RESET", "unknown-statement");
            return;
        }
        writePacket(output, 1, ok());
        record("COM_STMT_RESET", "RULE_GENERATED", "reset");
    }

    private void denyCommand(OutputStream output, String operation, String reason) throws IOException {
        writePacket(output, 1, error(1047, "08S01", reason));
        record(operation, "DENIED", reason);
    }

    private static void oneColumnResult(OutputStream output, String value) throws IOException {
        writePacket(output, 1, new byte[]{1});
        writePacket(output, 2, columnDefinition("veyrion_mock"));
        writePacket(output, 3, eof());
        ByteArrayOutputStream row = new ByteArrayOutputStream();
        lengthEncoded(row, value.getBytes(StandardCharsets.UTF_8));
        writePacket(output, 4, row.toByteArray());
        writePacket(output, 5, eof());
    }

    private static byte[] handshake(int connectionId) {
        byte[] seed = new byte[20];
        new SecureRandom().nextBytes(seed);
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(10);
        nul(value, "8.0.36-veyrion-mock");
        little(value, connectionId, 4);
        value.writeBytes(Arrays.copyOf(seed, 8));
        value.write(0);
        little(value, CAPABILITIES & 0xffff, 2);
        value.write(45);
        little(value, 2, 2);
        little(value, (CAPABILITIES >>> 16) & 0xffff, 2);
        value.write(21);
        value.writeBytes(new byte[10]);
        value.writeBytes(Arrays.copyOfRange(seed, 8, 20));
        value.write(0);
        nul(value, "mysql_native_password");
        return value.toByteArray();
    }

    private static byte[] ok() {
        return new byte[]{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    }

    private static byte[] eof() {
        return new byte[]{(byte) 0xfe, 0x00, 0x00, 0x02, 0x00};
    }

    private static byte[] error(int code, String state, String message) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(0xff);
        little(value, code, 2);
        value.write('#');
        value.writeBytes(state.getBytes(StandardCharsets.US_ASCII));
        value.writeBytes(message.getBytes(StandardCharsets.UTF_8));
        return value.toByteArray();
    }

    private static byte[] columnDefinition(String name) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        for (String part : new String[]{"def", "", "", "", name, ""}) {
            lengthEncoded(value, part.getBytes(StandardCharsets.UTF_8));
        }
        value.write(0x0c);
        little(value, 45, 2);
        little(value, 1024, 4);
        value.write(0xfd);
        little(value, 0, 2);
        value.write(0);
        value.write(0);
        value.write(0);
        return value.toByteArray();
    }

    private static String syntheticValue(String sql) {
        String normalized = sql.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        if (normalized.matches("select\\s+1(?:\\s*;)?")) return "1";
        if (normalized.contains("@@version") || normalized.contains("version()")) return "8.0.36-veyrion-mock";
        if (normalized.contains("database()")) return "veyrion";
        // Connector/J asks the server for transaction/read-only variables during pool startup.
        // Empty scalars are not protocol-compatible and fail Druid connection acquisition.
        if (normalized.contains("transaction_isolation")
                || normalized.contains("tx_isolation")) return "REPEATABLE-READ";
        if (normalized.contains("@@session.transaction_read_only")
                || normalized.contains("@@session.tx_read_only")
                || normalized.contains("@@global.read_only")
                || normalized.contains("@@read_only")) return "0";
        return "";
    }

    private static String firstKeyword(String sql) {
        String stripped = sql.stripLeading();
        while (stripped.startsWith("/*")) {
            int end = stripped.indexOf("*/", 2);
            if (end < 0) return "";
            stripped = stripped.substring(end + 2).stripLeading();
        }
        int end = 0;
        while (end < stripped.length() && Character.isLetter(stripped.charAt(end))) end++;
        return stripped.substring(0, end).toUpperCase(Locale.ROOT);
    }

    private static Packet readPacket(InputStream input) throws IOException {
        int first = input.read();
        if (first < 0) return null;
        int second = readByte(input);
        int third = readByte(input);
        int length = first | second << 8 | third << 16;
        int sequence = readByte(input);
        if (length <= 0 || length > MAX_PACKET_BYTES) throw new IOException("MySQL packet exceeds limit");
        byte[] payload = input.readNBytes(length);
        if (payload.length != length) throw new EOFException("short MySQL packet");
        return new Packet(sequence, payload);
    }

    private static void writePacket(OutputStream output, int sequence, byte[] payload) throws IOException {
        if (payload.length > MAX_PACKET_BYTES) throw new IOException("MySQL response exceeds limit");
        output.write(payload.length & 0xff);
        output.write(payload.length >>> 8 & 0xff);
        output.write(payload.length >>> 16 & 0xff);
        output.write(sequence & 0xff);
        output.write(payload);
        output.flush();
    }

    private static int readByte(InputStream input) throws IOException {
        int value = input.read();
        if (value < 0) throw new EOFException("short MySQL packet header");
        return value;
    }

    private static int littleInt(byte[] value, int offset) {
        if (offset < 0 || offset + 4 > value.length) throw new IllegalArgumentException("short integer");
        return value[offset] & 0xff | (value[offset + 1] & 0xff) << 8
                | (value[offset + 2] & 0xff) << 16 | (value[offset + 3] & 0xff) << 24;
    }

    private static void little(ByteArrayOutputStream output, long value, int bytes) {
        for (int index = 0; index < bytes; index++) output.write((int) (value >>> (index * 8)) & 0xff);
    }

    private static void nul(ByteArrayOutputStream output, String value) {
        output.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
        output.write(0);
    }

    private static void lengthEncoded(ByteArrayOutputStream output, byte[] value) {
        if (value.length < 251) {
            output.write(value.length);
        } else if (value.length <= 0xffff) {
            output.write(0xfc);
            little(output, value.length, 2);
        } else {
            output.write(0xfd);
            little(output, value.length, 3);
        }
        output.writeBytes(value);
    }

    private static void record(String operation, String outcome, String summary) {
        AgentRuntime.recordJdbc(LoopbackMysqlStub.class.getName(), "mysqlClassic",
                Map.of("captureMode", "DEPENDENCY_PROTOCOL_MOCK",
                        "dependencyMode", "MOCK",
                        "provenance", "RULE_GENERATED",
                        "protocol", "MYSQL_CLASSIC",
                        "operation", operation,
                        "outcome", outcome,
                        "summary", summary));
    }

    /** Statement-level D1 observation: truncated SQL text + class/outcome (not handshake meta). */
    private static void recordStatement(String operation, String outcome, String sqlClass,
                                        String sql, boolean parameterized) {
        String text = sql == null ? "" : sql.trim();
        if (text.length() > 256) text = text.substring(0, 256);
        String lower = text.toLowerCase(Locale.ROOT);
        String readWrite = lower.startsWith("select") || lower.startsWith("show")
                || lower.startsWith("explain") || lower.startsWith("describe") || lower.startsWith("desc")
                ? "READ"
                : lower.startsWith("insert") || lower.startsWith("update") || lower.startsWith("delete")
                || lower.startsWith("replace") || lower.startsWith("create") || lower.startsWith("alter")
                || lower.startsWith("drop") || lower.startsWith("truncate") ? "WRITE" : "UNKNOWN";
        boolean malicious = lower.contains("'\"veyrion-sqli-meta");
        String klass = sqlClass == null ? "" : sqlClass;
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("captureMode", "DEPENDENCY_PROTOCOL_MOCK");
        detail.put("dependencyMode", "MOCK");
        detail.put("provenance", "RULE_GENERATED");
        detail.put("protocol", "MYSQL_CLASSIC");
        detail.put("operation", operation);
        detail.put("outcome", outcome);
        detail.put("sqlClass", klass);
        detail.put("sql", text);
        detail.put("readWrite", readWrite);
        detail.put("parameterized", Boolean.toString(parameterized));
        detail.put("maliciousFragmentPresent", Boolean.toString(malicious));
        detail.put("parameterSummary", parameterized ? "jdbc-placeholders" : "inline");
        detail.put("summary", "sqlClass=" + klass + ",bytes=" + text.length());
        AgentRuntime.recordJdbc(LoopbackMysqlStub.class.getName(), "mysqlClassic", detail);
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

    private record Packet(int sequence, byte[] payload) { }

    private static final class Session {
        private final Map<Integer, byte[]> prepared = new LinkedHashMap<>();
        private int clientCapabilities;
        private int nextStatementId = 1;
    }
}
