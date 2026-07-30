package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.JdbcDataSourceSsrfFixture;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/**
 * kvf-shaped JDBC URL SSRF: DriverManagerDataSource#setUrl / #getConnection
 * must emit JDBC + EFFECT_TRIGGERED SSRF (not only DriverManager call sites).
 */
public final class JdbcDataSourceSsrfAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(25);

    private JdbcDataSourceSsrfAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        verifyEffectKindMapping();
        verifyCriticalBudgetRetention();

        Path work = Path.of("target", "jdbc-datasource-ssrf-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));

        verifyInstrumentedFixture(agentJar, work.resolve("fixture"));
        System.out.println("JdbcDataSourceSsrfAcceptanceTest: PASS");
    }

    private static void verifyEffectKindMapping() {
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC",
                        "org.springframework.jdbc.datasource.DriverManagerDataSource",
                        "setUrl")),
                "DriverManagerDataSource#setUrl → effectKind SSRF");
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC",
                        "org.springframework.jdbc.datasource.DriverManagerDataSource",
                        "getConnection")),
                "DriverManagerDataSource#getConnection → effectKind SSRF");
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC", "com.alibaba.druid.pool.DruidDataSource", "setUrl")),
                "DruidDataSource#setUrl → effectKind SSRF");
        check(!"SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC", "com.zaxxer.hikari.HikariDataSource", "getConnection")),
                "pooled Hikari getConnection must not be labeled SSRF");
        check(AgentRuntime.isJdbcUrlSsrfSink(
                        "org.springframework.jdbc.datasource.DriverManagerDataSource", "setUrl"),
                "isJdbcUrlSsrfSink recognizes Spring setUrl");
        check(AgentRuntime.isJdbcUrlSsrfSink("com.zaxxer.hikari.HikariConfig", "setJdbcUrl"),
                "isJdbcUrlSsrfSink recognizes Hikari setJdbcUrl");
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC", "com.zaxxer.hikari.HikariConfig", "setJdbcUrl")),
                "HikariConfig#setJdbcUrl → effectKind SSRF");
    }

    private static void verifyCriticalBudgetRetention() {
        Map<String, String> detail = PathDebugDetail.merge(
                Map.of(
                        "captureMode", "DATASOURCE_METHOD",
                        "operation", "setUrl",
                        "url", "jdbc:mysql://127.0.0.1:3306/veyrion"),
                PathDebugDetail.effectTriggered("SSRF"));
        check(EventWriter.isCriticalEffect("JDBC", detail),
                "DATASOURCE_METHOD setUrl SSRF survives maxEvents soft-stop");
    }

    private static void verifyInstrumentedFixture(Path agentJar, Path traceDirectory)
            throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, JdbcDataSourceSsrfFixture.class,
                "maxEvents=80,maxBytes=65536,classPrefix=com.aq.fixture", true);
        check(result.exitCode == 0, "fixture failed: " + result.output);
        check(result.output.contains("JdbcDataSourceSsrfFixture: PASS"),
                "fixture did not complete");
        List<String> lines = Files.readAllLines(
                traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME), StandardCharsets.UTF_8);
        String all = String.join("\n", lines);
        check(all.contains("\"eventType\":\"JDBC\""), "JDBC event missing");
        check(all.contains("DriverManagerDataSource"),
                "DriverManagerDataSource must appear in JDBC observation");
        check(all.contains("\"pathDebugKind\":\"EFFECT_TRIGGERED\""),
                "EFFECT_TRIGGERED marker required for H4");
        check(all.contains("\"effectKind\":\"SSRF\""),
                "effectKind SSRF required (not SQL-only)");
        check(all.contains("setUrl") || all.contains("getConnection"),
                "setUrl or getConnection operation must be observed");
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(JdbcDataSourceSsrfAcceptanceTest.class);
        Path byteBuddyClasses = codeSource(net.bytebuddy.agent.builder.AgentBuilder.class);
        List<String> command = new ArrayList<>();
        command.add(java.toString());
        command.add("-D" + AgentConfig.TRACE_DIR_PROPERTY + "=" + traceDirectory);
        command.add("-Dveyrion.fixture.output=" + traceDirectory.resolve("fixture-output.txt"));
        if (authorize) {
            command.add("-D" + AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY + "=true");
            command.add("-Dveyrion.sandbox.docker=true");
        }
        command.add("-javaagent:" + agentJar + "=" + agentArguments);
        command.add("-cp");
        command.add(testClasses + System.getProperty("path.separator") + mainClasses
                + System.getProperty("path.separator") + byteBuddyClasses);
        command.add(fixtureClass.getName());

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(CHILD_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        if (!exited) {
            process.destroyForcibly();
            throw new AssertionError("fixture child JVM timed out");
        }
        String output;
        try (InputStream stream = process.getInputStream()) {
            output = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        return new ProcessResult(process.exitValue(), output);
    }

    private static Path createAgentJar(Path target) throws Exception {
        Path classes = codeSource(VeyrionAgent.class);
        Manifest manifest = new Manifest();
        Attributes attributes = manifest.getMainAttributes();
        attributes.put(Attributes.Name.MANIFEST_VERSION, "1.0");
        attributes.putValue("Premain-Class", VeyrionAgent.class.getName());
        attributes.putValue("Agent-Class", VeyrionAgent.class.getName());
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(target), manifest);
             Stream<Path> paths = Files.walk(classes)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                String entryName = classes.relativize(path).toString().replace('\\', '/');
                if (!entryName.endsWith(".class")) {
                    continue;
                }
                jar.putNextEntry(new JarEntry(entryName));
                Files.copy(path, jar);
                jar.closeEntry();
            }
        }
        return target;
    }

    private static Path codeSource(Class<?> type) throws URISyntaxException {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    private static void deleteRecursively(Path path) throws Exception {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(path)) {
            for (Path entry : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(entry);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private record ProcessResult(int exitCode, String output) {
    }
}
