package com.aq.jvmsentinel.instrumentation;

import com.aq.jvmsentinel.instrumentation.mock.LoopbackMysqlStub;
import com.aq.jvmsentinel.instrumentation.mock.LoopbackRedisStub;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Socket-level checks for the deliberately bounded RESP and MySQL protocol subsets. */
public final class ProtocolSubstituteAcceptanceTest {
    private ProtocolSubstituteAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        redisResp2And3();
        mysqlClassic();
        System.out.println("ProtocolSubstituteAcceptanceTest: PASS");
    }

    private static void redisResp2And3() throws Exception {
        try (LoopbackRedisStub stub = LoopbackRedisStub.start(0);
             Socket socket = new Socket("127.0.0.1", stub.port())) {
            socket.setSoTimeout(3000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            sendResp(out, "HELLO", "3");
            String helloHeader = readLine(in);
            check(helloHeader.charAt(0) == '%', "RESP3 HELLO map");
            drainResp3Map(in, helloHeader);
            sendResp(out, "SET", "session:key", "value");
            check(readLine(in).equals("+OK"), "RESP SET");
            sendResp(out, "GET", "session:key");
            check(readLine(in).equals("$5") && readBytes(in, 5).equals("value"), "RESP GET");
            check(readLine(in).isEmpty(), "RESP bulk trailer");
            sendResp(out, "NO_SUCH_COMMAND");
            check(readLine(in).startsWith("-ERR"), "unknown Redis command rejected");
        }
        try (LoopbackRedisStub stub = LoopbackRedisStub.start(0);
             Socket socket = new Socket("127.0.0.1", stub.port())) {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            sendResp(out, "PING");
            check(readLine(in).equals("+PONG"), "RESP2 PING");
            sendResp(out, "EVAL", "return 1");
            check(readLine(in).startsWith("-ERR"), "unknown Redis command rejected in RESP2");
        }
    }

    private static void mysqlClassic() throws Exception {
        try (LoopbackMysqlStub stub = LoopbackMysqlStub.start(0);
             Socket socket = new Socket("127.0.0.1", stub.port())) {
            socket.setSoTimeout(3000);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            Packet handshake = readPacket(in);
            check((handshake.payload()[0] & 0xff) == 10, "MySQL protocol handshake");
            ByteArrayOutputStream login = new ByteArrayOutputStream();
            little(login, 0x003aa20d, 4);
            little(login, 1024 * 1024, 4);
            login.write(45);
            login.write(new byte[23]);
            login.writeBytes("veyrion".getBytes(StandardCharsets.US_ASCII));
            login.write(0);
            login.write(0);
            sendPacket(out, 1, login.toByteArray());
            check((readPacket(in).payload()[0] & 0xff) == 0, "MySQL login accepted");
            sendPacket(out, 0, concat(new byte[]{3}, "SELECT 1".getBytes(StandardCharsets.US_ASCII)));
            check((readPacket(in).payload()[0] & 0xff) == 1, "COM_QUERY result set");
            readPacket(in); readPacket(in); readPacket(in); readPacket(in);
            sendPacket(out, 0, concat(new byte[]{0x16}, "SELECT ?".getBytes(StandardCharsets.US_ASCII)));
            Packet prepared = readPacket(in);
            check((prepared.payload()[0] & 0xff) == 0, "COM_STMT_PREPARE");
            int statementId = little(prepared.payload(), 1);
            readPacket(in); readPacket(in);
            ByteArrayOutputStream execute = new ByteArrayOutputStream();
            execute.write(0x17); little(execute, statementId, 4); execute.write(0); little(execute, 1, 4);
            sendPacket(out, 0, execute.toByteArray());
            check((readPacket(in).payload()[0] & 0xff) == 1, "COM_STMT_EXECUTE result set");
            readPacket(in); readPacket(in); readPacket(in); readPacket(in);
            sendPacket(out, 0, new byte[]{0x0e});
            Packet ping = readPacket(in);
            check((ping.payload()[0] & 0xff) == 0, "COM_PING");
            sendPacket(out, 0, new byte[]{0x55});
            check((readPacket(in).payload()[0] & 0xff) == 0xff, "unknown MySQL command rejected");
            sendPacket(out, 0, new byte[]{1});
        }
    }

    private static void sendResp(OutputStream out, String... values) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(("*" + values.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
        for (String value : values) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            body.write(("$" + bytes.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            body.write(bytes); body.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        }
        out.write(body.toByteArray()); out.flush();
    }

    private static void drainResp3Map(InputStream in, String header) throws IOException {
        int count = Integer.parseInt(header.substring(1));
        for (int i = 0; i < count * 2; i++) {
            String fieldHeader = readLine(in);
            if (fieldHeader.startsWith("$")) {
                int length = Integer.parseInt(fieldHeader.substring(1));
                readBytes(in, length); readLine(in);
            }
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int previous = -1;
        while (true) {
            int current = in.read();
            if (current < 0) throw new EOFException();
            if (previous == '\r' && current == '\n') {
                byte[] value = bytes.toByteArray();
                return new String(value, 0, value.length - 1, StandardCharsets.UTF_8);
            }
            bytes.write(current); previous = current;
        }
    }

    private static String readBytes(InputStream in, int length) throws IOException {
        byte[] value = in.readNBytes(length);
        if (value.length != length) throw new EOFException();
        return new String(value, StandardCharsets.UTF_8);
    }

    private static Packet readPacket(InputStream in) throws IOException {
        int a = in.read(), b = in.read(), c = in.read(), sequence = in.read();
        if (a < 0 || b < 0 || c < 0 || sequence < 0) throw new EOFException();
        int length = a | b << 8 | c << 16;
        byte[] payload = in.readNBytes(length);
        if (payload.length != length) throw new EOFException();
        return new Packet(sequence, payload);
    }

    private static void sendPacket(OutputStream out, int sequence, byte[] payload) throws IOException {
        out.write(payload.length & 0xff); out.write(payload.length >>> 8 & 0xff);
        out.write(payload.length >>> 16 & 0xff); out.write(sequence); out.write(payload); out.flush();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static void little(ByteArrayOutputStream out, long value, int bytes) {
        for (int i = 0; i < bytes; i++) out.write((int) (value >>> (i * 8)) & 0xff);
    }

    private static int little(byte[] value, int offset) {
        return value[offset] & 0xff | (value[offset + 1] & 0xff) << 8
                | (value[offset + 2] & 0xff) << 16 | (value[offset + 3] & 0xff) << 24;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record Packet(int sequence, byte[] payload) { }
}
