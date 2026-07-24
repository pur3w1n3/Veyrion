package com.aq.jvmsentinel.agent;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

/** Fixed loopback-only HTTP stimulus used inside the deny-all Docker container. */
public final class LoopbackHttpProbe {
    private static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final byte[] SYNTHETIC_BODY =
            "{\"marker\":\"synthetic-http-entry-v1\"}".getBytes(StandardCharsets.US_ASCII);

    private LoopbackHttpProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("method and route are required");
        String method = args[0].toUpperCase(Locale.ROOT);
        String route = args[1];
        if (!METHODS.contains(method)
                || !route.matches("/[A-Za-z0-9_./{}:-]{0,1023}")) {
            throw new IllegalArgumentException("probe target is invalid");
        }
        byte[] body = Set.of("POST", "PUT", "PATCH").contains(method)
                ? SYNTHETIC_BODY : new byte[0];
        try (Socket socket = new Socket()) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, 8080), 2_000);
            socket.setSoTimeout(2_000);
            OutputStream output = socket.getOutputStream();
            String headers = method + " " + route + " HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\nConnection: close\r\n"
                    + "Content-Type: application/json\r\nContent-Length: " + body.length + "\r\n\r\n";
            output.write(headers.getBytes(StandardCharsets.US_ASCII));
            output.write(body);
            output.flush();
            InputStream input = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int total = 0;
            int read;
            while (total < MAX_RESPONSE_BYTES
                    && (read = input.read(buffer, 0,
                    Math.min(buffer.length, MAX_RESPONSE_BYTES - total))) >= 0) {
                total += read;
            }
        }
    }
}
