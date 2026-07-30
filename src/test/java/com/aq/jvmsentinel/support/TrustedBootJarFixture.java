package com.aq.jvmsentinel.support;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 为 TRUSTED_DOCKER live probe 构建最小可执行“Boot-shaped”JAR：
 * Main-Class 承载两 HTTP route；BOOT-INF 带 Spring stub 供 static entry discovery。
 */
public final class TrustedBootJarFixture {
    public static final String MAIN_CLASS = "com.aq.veyrion.fixture.TrustedMultiEntryApp";

    private TrustedBootJarFixture() {
    }

    public static Path build(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        write(sources, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        write(sources, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        write(sources, "app/ApiAController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class ApiAController {
                    @GetMapping("/api/a")
                    public String a(String q) { return q == null ? "a" : q; }
                }
                """);
        write(sources, "app/ApiBController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class ApiBController {
                    @GetMapping("/api/b")
                    public String b(String q) { return q == null ? "b" : q; }
                }
                """);
        write(sources, "com/aq/veyrion/fixture/TrustedMultiEntryApp.java", """
                package com.aq.veyrion.fixture;
                import com.sun.net.httpserver.Headers;
                import com.sun.net.httpserver.HttpExchange;
                import com.sun.net.httpserver.HttpServer;
                import java.io.IOException;
                import java.io.OutputStream;
                import java.net.InetSocketAddress;
                import java.nio.charset.StandardCharsets;
                import java.sql.Connection;
                import java.sql.DriverManager;
                import java.sql.Statement;
                import java.lang.reflect.Method;
                public final class TrustedMultiEntryApp {
                    public static void main(String[] args) throws Exception {
                        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
                        server.createContext("/api/a", exchange -> handle(exchange,
                                "SELECT marker_a FROM t_a WHERE id=1"));
                        server.createContext("/api/b", exchange -> handle(exchange,
                                "SELECT marker_b FROM t_b WHERE id=2"));
                        server.createContext("/", exchange -> {
                            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
                            exchange.sendResponseHeaders(200, body.length);
                            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                        });
                        server.start();
                        Thread.currentThread().join();
                    }
                    private static void handle(HttpExchange exchange, String sql) throws IOException {
                        try {
                            bindCorrelation(exchange.getRequestHeaders());
                            executeSql(sql);
                            byte[] body = ("ok:" + sql.hashCode()).getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/plain");
                            exchange.sendResponseHeaders(200, body.length);
                            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                        } catch (Exception failure) {
                            byte[] body = ("err:" + failure.getClass().getSimpleName())
                                    .getBytes(StandardCharsets.UTF_8);
                            exchange.sendResponseHeaders(500, body.length);
                            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                        } finally {
                            releaseCorrelation();
                        }
                    }
                    private static void executeSql(String sql) throws Exception {
                        try {
                            Class.forName("com.aq.jvmsentinel.instrumentation.mock.VeyrionMockDriver");
                        } catch (ClassNotFoundException ignored) { }
                        try (Connection connection = DriverManager.getConnection("jdbc:veyrion-mock:live");
                             Statement statement = connection.createStatement()) {
                            statement.execute(sql);
                        } catch (Exception fallback) {
                            // 无 agent mock driver 仍保持进程就绪供 HTTP probe。
                        }
                    }
                    private static void bindCorrelation(Headers headers) {
                        try {
                            String correlation = headers.getFirst("X-Veyrion-Correlation-Id");
                            if (correlation == null || correlation.isBlank()) return;
                            Class<?> runtime = Class.forName(
                                    "com.aq.jvmsentinel.instrumentation.AgentRuntime");
                            Method bind = runtime.getMethod("bindRequestCorrelation", String.class);
                            bind.invoke(null, correlation);
                        } catch (ReflectiveOperationException ignored) { }
                    }
                    private static void releaseCorrelation() {
                        try {
                            Class<?> runtime = Class.forName(
                                    "com.aq.jvmsentinel.instrumentation.AgentRuntime");
                            Method release = runtime.getMethod("releaseRequestCorrelation");
                            release.invoke(null);
                        } catch (ReflectiveOperationException ignored) { }
                    }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("trusted-boot-multi-entry.jar");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, MAIN_CLASS);
        manifest.getMainAttributes().putValue("Start-Class", MAIN_CLASS);
        manifest.getMainAttributes().putValue("Spring-Boot-Version", "3.3.0-fixture");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            output.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            manifest.write(output);
            output.closeEntry();
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                String relative = classes.relativize(file).toString().replace('\\', '/');
                // Runtime Main-Class 须从 JAR root classpath 加载。
                if (relative.startsWith("com/aq/veyrion/fixture/")) {
                    output.putNextEntry(new ZipEntry(relative));
                    Files.copy(file, output);
                    output.closeEntry();
                }
                output.putNextEntry(new ZipEntry("BOOT-INF/classes/" + relative));
                Files.copy(file, output);
                output.closeEntry();
            }
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/application.properties"));
            output.write("server.port=8080\n".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            output.putNextEntry(new ZipEntry("org/springframework/boot/loader/launch/JarLauncher.class"));
            output.write(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 55});
            output.closeEntry();
        }
        return jar;
    }

    private static void write(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("TrustedBootJarFixture requires a JDK compiler");
        }
        List<Path> files;
        try (Stream<Path> stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(files)).call();
            if (!success) {
                throw new IllegalStateException("TrustedBootJarFixture compilation failed");
            }
        }
    }
}
