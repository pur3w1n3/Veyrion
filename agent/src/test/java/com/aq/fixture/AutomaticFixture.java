package com.aq.fixture;

import jakarta.servlet.Servlet;
import org.springframework.web.bind.annotation.GetMapping;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Statement;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/** Harmless fixture: no explicit AgentRuntime calls and no network access. */
public final class AutomaticFixture implements Servlet {
    private static volatile int branchResult;

    private AutomaticFixture() {
    }

    public static void main(String[] args) throws Exception {
        AutomaticFixture fixture = new AutomaticFixture();
        fixture.handler();
        fixture.service();

        FixtureStatement statement = (FixtureStatement) java.lang.reflect.Proxy.newProxyInstance(
                AutomaticFixture.class.getClassLoader(),
                new Class<?>[]{FixtureStatement.class},
                (proxy, method, arguments) -> primitiveDefault(method.getReturnType()));
        statement.execute("SELECT 1");

        HttpClient client = new LocalHttpClient();
        client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1/")).build(),
                HttpResponse.BodyHandlers.discarding());

        Path output = Path.of(System.getProperty("veyrion.fixture.output"));
        Files.writeString(output, "fixture", StandardCharsets.UTF_8);

        String java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java").toString();
        Process first = new ProcessBuilder(java, "-version")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        check(first.waitFor() == 0, "ProcessBuilder child failed");
        Process second = Runtime.getRuntime().exec(new String[]{java, "-version"});
        check(second.waitFor() == 0, "Runtime.exec child failed");
        System.out.println("AutomaticFixture: PASS");
    }

    @GetMapping
    public void handler() {
        // Exercise branches inside a Spring-mapped HTTP surface so coverage scopes flush.
        branchResult = branchWork(7);
    }

    @Override
    public void service() {
        branchResult = branchWork(7);
    }

    private static int branchWork(int value) {
        int result = value > 0 ? 1 : -1;
        switch (value) {
            case 6 -> result += 6;
            case 7 -> result += 7;
            default -> result = 0;
        }
        return result;
    }

    private static Object primitiveDefault(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == char.class) return '\0';
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        return 0D;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static final class LocalHttpClient extends HttpClient {
        @Override public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
        @Override public Optional<Duration> connectTimeout() { return Optional.empty(); }
        @Override public Redirect followRedirects() { return Redirect.NEVER; }
        @Override public Optional<ProxySelector> proxy() { return Optional.empty(); }
        @Override public SSLContext sslContext() { return null; }
        @Override public SSLParameters sslParameters() { return new SSLParameters(); }
        @Override public Optional<Authenticator> authenticator() { return Optional.empty(); }
        @Override public Version version() { return Version.HTTP_1_1; }
        @Override public Optional<Executor> executor() { return Optional.empty(); }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
            return null;
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler,
                HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
            return CompletableFuture.completedFuture(null);
        }
    }
}

interface FixtureStatement extends Statement {
}
