package com.aq.fixture;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 练习 JDK 底层汇聚点（应用 call-site）：写/读/反序列化/URL 出站。
 * 无显式 AgentRuntime 调用；绑定 correlation 以放行 FILE_READ 门控。
 */
public final class JdkConvergenceFixture implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String marker;

    public JdkConvergenceFixture() {
        this.marker = "veyrion-jdk";
    }

    public static void main(String[] args) throws Exception {
        // 模拟请求线程：有 correlation 时 FILE_READ 才出轨（噪音门控）。
        com.aq.jvmsentinel.instrumentation.AgentRuntime.bindRequestCorrelation("req-jdk-conv-1");
        try {
            Path dir = Path.of(System.getProperty("veyrion.fixture.output", "target/jdk-conv-out"))
                    .toAbsolutePath().normalize().getParent();
            if (dir == null) {
                dir = Path.of("target").toAbsolutePath();
            }
            Files.createDirectories(dir);
            Path writeTarget = dir.resolve("veyrion-jdk-write.bin");
            Path readSource = dir.resolve("veyrion-jdk-read.txt");
            Files.writeString(readSource, "read-me", StandardCharsets.UTF_8);

            try (FileOutputStream out = new FileOutputStream(writeTarget.toFile())) {
                out.write("w".getBytes(StandardCharsets.UTF_8));
            }
            Files.writeString(dir.resolve("veyrion-jdk-files-write.txt"), "files-write",
                    StandardCharsets.UTF_8);

            try (FileInputStream in = new FileInputStream(readSource.toFile())) {
                check(in.read() >= 0, "FileInputStream must read");
            }

            byte[] serialized;
            try (java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                 java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos)) {
                oos.writeObject(new JdkConvergenceFixture());
                serialized = bos.toByteArray();
            }
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
                Object obj = ois.readObject();
                check(obj instanceof JdkConvergenceFixture, "readObject round-trip");
            }

            // 出站：构造 URL 并 openConnection（不 connect 外网；loopback 即可）。
            URL url = new URL("http://127.0.0.1:9/veyrion-ssrf-probe");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(50);
            conn.setReadTimeout(50);
            try {
                conn.connect();
            } catch (Exception ignored) {
                // 预期失败；观测点在 openConnection/connect call-site。
            } finally {
                conn.disconnect();
            }

            System.out.println("JdkConvergenceFixture: PASS");
        } finally {
            com.aq.jvmsentinel.instrumentation.AgentRuntime.releaseRequestCorrelation();
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
