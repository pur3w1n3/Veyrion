package com.aq.jvmsentinel.substitute;

import com.aq.jvmsentinel.substitute.DependencySubstitutionPolicy.FileGrant;
import com.aq.jvmsentinel.substitute.DependencySubstitutionPolicy.HttpRoute;
import com.aq.jvmsentinel.substitute.DependencySubstitutionPolicy.JdbcRule;
import com.aq.jvmsentinel.substitute.DependencySubstitutionPolicy.ProcessSimulation;
import com.aq.jvmsentinel.substitute.DependencySubstitutionTranscript.Kind;
import com.aq.jvmsentinel.substitute.DependencySubstitutionTranscript.StopReason;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 离线 substitution runtime。永不打开 outbound socket、加载 JDBC driver、
 * 接受 database URL 或调用 host process。
 */
public final class DependencySubstitutionEngine implements AutoCloseable {
    public record JdbcResult(List<String> columns, List<List<String>> rows) {
        public JdbcResult {
            columns = List.copyOf(columns);
            rows = rows.stream().map(List::copyOf).toList();
        }
    }

    public record ProcessResult(boolean simulated, int exitCode, String stdout, String stderr) { }

    private final DependencySubstitutionPolicy policy;
    private final DependencySubstitutionTranscript transcript;
    private final Path tmpfsRoot;
    private final Map<String, HttpRoute> httpRoutes = new LinkedHashMap<>();
    private final Map<String, JdbcRule> jdbcRules = new LinkedHashMap<>();
    private final Map<String, FileGrant> fileGrants = new LinkedHashMap<>();
    private final Map<String, ProcessSimulation> processSimulations = new LinkedHashMap<>();
    private HttpServer httpServer;
    private ExecutorService httpExecutor;

    public DependencySubstitutionEngine(DependencySubstitutionPolicy policy, Path tmpfsRoot) throws IOException {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.transcript = new DependencySubstitutionTranscript(policy);
        this.tmpfsRoot = Objects.requireNonNull(tmpfsRoot, "tmpfsRoot").toAbsolutePath().normalize();
        initializeRoot();
        for (HttpRoute route : policy.httpRoutes()) {
            requireBodyBudget(route.responseBody());
            httpRoutes.put(route.method() + " " + route.path(), route);
        }
        policy.jdbcRules().forEach(rule -> jdbcRules.put(rule.normalizedSql(), rule));
        for (FileGrant grant : policy.fileGrants()) {
            requireBodyBudget(grant.seedContent());
            fileGrants.put(grant.relativePath(), grant);
            seed(grant);
        }
        policy.processSimulations().forEach(simulation -> processSimulations.put(simulation.key(), simulation));
    }

    public synchronized URI startHttpMock() throws IOException {
        if (httpServer != null) return URI.create("http://127.0.0.1:" + httpServer.getAddress().getPort() + "/");
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        if (!loopback.isLoopbackAddress()) throw new SecurityException("HTTP mock address is not loopback");
        HttpServer server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "dependency-substitution-http");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
        server.createContext("/", this::handleHttp);
        server.start();
        httpServer = server;
        httpExecutor = executor;
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    }

    public JdbcResult jdbcQuery(String sql, List<?> parameters) {
        String normalized = DependencySubstitutionPolicy.normalizeSql(sql);
        JdbcRule rule = jdbcRules.get(normalized);
        String request = "sqlSha256=" + DependencySubstitutionTranscript.sha256(normalized)
                + ",sqlSummary=" + sqlSummary(normalized)
                + ",parameters=" + parameterSummary(parameters);
        if (rule == null) {
            transcript.append(Kind.JDBC, "QUERY", request, "DENY:no fixed SQL rule",
                    DependencySubstitutionPolicy.Provenance.RULE_GENERATED, false, StopReason.POLICY_REJECTED);
            throw new SecurityException("JDBC query has no fixed substitution rule");
        }
        String response = "columns=" + rule.columns().size() + ",rows=" + rule.rows().size()
                + ",resultSha256=" + DependencySubstitutionTranscript.sha256(rule.rows().toString());
        transcript.append(Kind.JDBC, "QUERY", request, response, rule.provenance(), true, StopReason.CONTINUE);
        return new JdbcResult(rule.columns(), rule.rows());
    }

    public byte[] readFile(String relativePath) throws IOException {
        FileGrant grant = fileGrants.get(relativePath);
        if (grant == null || !grant.readable()) {
            transcript.append(Kind.FILE, "READ", "path=" + safePathLabel(relativePath), "DENY:not granted",
                    DependencySubstitutionPolicy.Provenance.RULE_GENERATED, false, StopReason.POLICY_REJECTED);
            throw new SecurityException("file read is not granted");
        }
        Path path = authorizedPath(grant);
        byte[] content = Files.readAllBytes(path);
        if (content.length > policy.budget().maxBodyBytes()) {
            transcript.append(Kind.FILE, "READ", "path=" + grant.relativePath(), "DENY:body budget",
                    grant.provenance(), false, StopReason.BUDGET_EXHAUSTED);
            throw new DependencySubstitutionTranscript.BudgetExceededException("file exceeds body budget");
        }
        transcript.append(Kind.FILE, "READ", "path=" + grant.relativePath(),
                DependencySubstitutionTranscript.summarize("content", content),
                grant.provenance(), true, StopReason.CONTINUE);
        return content;
    }

    public void writeFile(String relativePath, byte[] content) throws IOException {
        Objects.requireNonNull(content, "content");
        FileGrant grant = fileGrants.get(relativePath);
        if (grant == null || !grant.writable()) {
            transcript.append(Kind.FILE, "WRITE", "path=" + safePathLabel(relativePath),
                    "DENY:not granted", DependencySubstitutionPolicy.Provenance.RULE_GENERATED,
                    false, StopReason.POLICY_REJECTED);
            throw new SecurityException("file write is not granted");
        }
        if (content.length > policy.budget().maxBodyBytes()) {
            transcript.append(Kind.FILE, "WRITE", "path=" + grant.relativePath(),
                    "DENY:body budget", grant.provenance(), false, StopReason.BUDGET_EXHAUSTED);
            throw new DependencySubstitutionTranscript.BudgetExceededException("file exceeds body budget");
        }
        Path path = authorizedPath(grant);
        Files.write(path, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        transcript.append(Kind.FILE, "WRITE", "path=" + grant.relativePath(),
                DependencySubstitutionTranscript.summarize("content", content),
                grant.provenance(), true, StopReason.CONTINUE);
    }

    public ProcessResult process(List<String> argv) {
        Objects.requireNonNull(argv, "argv");
        String key = String.join("\u0000", argv);
        ProcessSimulation simulation = processSimulations.get(key);
        String request = "argvCount=" + argv.size() + ",argvSha256="
                + DependencySubstitutionTranscript.sha256(key);
        if (simulation == null) {
            transcript.append(Kind.PROCESS, "START", request, "DENY:process default policy",
                    DependencySubstitutionPolicy.Provenance.RULE_GENERATED, false, StopReason.POLICY_REJECTED);
            throw new SecurityException("process execution is denied");
        }
        String response = "simulated=true,exitCode=" + simulation.exitCode() + ",stdout="
                + DependencySubstitutionTranscript.summarize("value",
                simulation.stdout().getBytes(StandardCharsets.UTF_8)) + ",stderr="
                + DependencySubstitutionTranscript.summarize("value",
                simulation.stderr().getBytes(StandardCharsets.UTF_8));
        transcript.append(Kind.PROCESS, "START", request, response, simulation.provenance(),
                true, StopReason.CONTINUE);
        return new ProcessResult(true, simulation.exitCode(), simulation.stdout(), simulation.stderr());
    }

    public DependencySubstitutionTranscript transcript() {
        return transcript;
    }

    public void complete() {
        transcript.complete();
    }

    private void handleHttp(HttpExchange exchange) throws IOException {
        byte[] requestBody;
        try {
            requestBody = readBounded(exchange);
        } catch (DependencySubstitutionTranscript.BudgetExceededException exceeded) {
            send(exchange, 413, "text/plain", "request too large");
            return;
        }
        String method = exchange.getRequestMethod().toUpperCase(java.util.Locale.ROOT);
        String path = exchange.getRequestURI().getRawPath();
        HttpRoute route = exchange.getRequestURI().getRawQuery() == null
                ? httpRoutes.get(method + " " + path) : null;
        String request = "method=" + method + ",path=" + path + ","
                + DependencySubstitutionTranscript.summarize("body", requestBody)
                + ",authorization=" + exchange.getRequestHeaders().getFirst("Authorization");
        if (route == null) {
            try {
                transcript.append(Kind.HTTP, "REQUEST", request, "DENY:no fixed route",
                        DependencySubstitutionPolicy.Provenance.RULE_GENERATED, false, StopReason.POLICY_REJECTED);
            } finally {
                send(exchange, 404, "text/plain", "not found");
            }
            return;
        }
        byte[] response = route.responseBody().getBytes(StandardCharsets.UTF_8);
        transcript.append(Kind.HTTP, "REQUEST", request,
                "status=" + route.status() + "," + DependencySubstitutionTranscript.summarize("body", response),
                route.provenance(), true, StopReason.CONTINUE);
        send(exchange, route.status(), route.contentType(), route.responseBody());
    }

    private byte[] readBounded(HttpExchange exchange) throws IOException {
        int max = Math.toIntExact(policy.budget().maxBodyBytes());
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(max, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = exchange.getRequestBody().read(buffer)) != -1) {
            total += read;
            if (total > max) {
                transcript.append(Kind.HTTP, "REQUEST", "method=" + exchange.getRequestMethod(),
                        "DENY:body budget", DependencySubstitutionPolicy.Provenance.RULE_GENERATED,
                        false, StopReason.BUDGET_EXHAUSTED);
                throw new DependencySubstitutionTranscript.BudgetExceededException("HTTP body exceeds budget");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("X-Veyrion-Dependency-Mode", "substitution");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private void initializeRoot() throws IOException {
        Files.createDirectories(tmpfsRoot);
        if (Files.isSymbolicLink(tmpfsRoot) || !Files.isDirectory(tmpfsRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("tmpfs root must be a real directory");
        }
    }

    private void seed(FileGrant grant) throws IOException {
        Path path = authorizedPath(grant);
        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        verifyNoSymlinks(path, false);
        Files.writeString(path, grant.seedContent(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private Path authorizedPath(FileGrant grant) throws IOException {
        Path resolved = tmpfsRoot.resolve(grant.relativePath()).normalize();
        if (!resolved.startsWith(tmpfsRoot)) throw new SecurityException("file escaped tmpfs root");
        verifyNoSymlinks(resolved, true);
        return resolved;
    }

    private void verifyNoSymlinks(Path path, boolean allowMissingLeaf) throws IOException {
        Path current = tmpfsRoot;
        Path relative = tmpfsRoot.relativize(path);
        for (int index = 0; index < relative.getNameCount(); index++) {
            current = current.resolve(relative.getName(index));
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (allowMissingLeaf && index == relative.getNameCount() - 1) return;
                continue;
            }
            if (Files.isSymbolicLink(current)) throw new SecurityException("symbolic links are forbidden");
        }
    }

    private void requireBodyBudget(String value) {
        if (value.getBytes(StandardCharsets.UTF_8).length > policy.budget().maxBodyBytes()) {
            throw new IllegalArgumentException("configured body exceeds maxBodyBytes");
        }
    }

    private static String parameterSummary(List<?> parameters) {
        Objects.requireNonNull(parameters, "parameters");
        if (parameters.size() > 128) throw new IllegalArgumentException("too many JDBC parameters");
        List<String> summaries = new ArrayList<>(parameters.size());
        for (Object parameter : parameters) {
            if (parameter == null) {
                summaries.add("null");
            } else {
                String value = String.valueOf(parameter);
                if (value.length() > 4096) throw new IllegalArgumentException("JDBC parameter is too large");
                summaries.add(parameter.getClass().getSimpleName() + ":"
                        + DependencySubstitutionTranscript.sha256(value));
            }
        }
        return summaries.toString();
    }

    private static String sqlSummary(String normalizedSql) {
        int separator = normalizedSql.indexOf(' ');
        String verb = separator < 0 ? normalizedSql : normalizedSql.substring(0, separator);
        long placeholders = normalizedSql.chars().filter(character -> character == '?').count();
        return "verb=" + verb.replaceAll("[^a-z]", "") + "|placeholders=" + placeholders
                + "|length=" + normalizedSql.length();
    }

    private static String safePathLabel(String path) {
        if (path == null) return "<null>";
        return "sha256:" + DependencySubstitutionTranscript.sha256(path);
    }

    @Override
    public synchronized void close() {
        if (httpServer != null) {
            httpServer.stop(0);
            httpServer = null;
        }
        if (httpExecutor != null) {
            httpExecutor.shutdownNow();
            httpExecutor = null;
        }
    }
}
