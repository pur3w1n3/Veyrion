package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.ExpressionEvalFixture;
import com.aq.fixture.HikariJdbcUrlFixture;
import com.aq.fixture.RestTemplateSsrfFixture;

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
 * AGENT-PROBE-COVERAGE-PASS: Hikari setJdbcUrl / RestTemplate / SpEL Expression
 * must emit EFFECT_TRIGGERED outside application classPrefix (same class of gap as
 * DriverManagerDataSource#setUrl and MultipartFile#transferTo).
 */
public final class AgentEffectSurfaceCoverageAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(25);

    private AgentEffectSurfaceCoverageAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        verifyEffectKindMapping();
        verifyCriticalBudgetRetention();

        Path work = Path.of("target", "agent-effect-surface-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));

        verifyInstrumentedFixture(agentJar, work.resolve("hikari"), HikariJdbcUrlFixture.class,
                "JDBC", "setJdbcUrl", "SSRF", "HikariConfig");
        verifyInstrumentedFixture(agentJar, work.resolve("rest"), RestTemplateSsrfFixture.class,
                "HTTP_CLIENT", "getForObject", "SSRF", "RestTemplate");
        verifyInstrumentedFixture(agentJar, work.resolve("spel"), ExpressionEvalFixture.class,
                "PROCESS", "getValue", "EXPRESSION", "SpelExpression");
        System.out.println("AgentEffectSurfaceCoverageAcceptanceTest: PASS");
    }

    private static void verifyEffectKindMapping() {
        check(AgentRuntime.isJdbcUrlSsrfSink("com.zaxxer.hikari.HikariConfig", "setJdbcUrl"),
                "HikariConfig#setJdbcUrl recognized");
        check(AgentRuntime.isJdbcUrlSsrfSink("com.zaxxer.hikari.HikariDataSource", "setJdbcUrl"),
                "HikariDataSource#setJdbcUrl recognized");
        check(!"SSRF".equals(AgentRuntime.primaryEffectKind(
                        "JDBC", "com.zaxxer.hikari.HikariDataSource", "getConnection")),
                "pooled Hikari getConnection must not be SSRF");
        check(AgentRuntime.isHttpClientSsrfSink(
                        "org.springframework.web.client.RestTemplate", "exchange"),
                "RestTemplate#exchange recognized");
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "HTTP_CLIENT",
                        "org.springframework.web.client.RestTemplate",
                        "getForObject")),
                "RestTemplate → effectKind SSRF");
        check(AgentRuntime.isExpressionEvalSink(
                        "org.springframework.expression.spel.standard.SpelExpression",
                        "getValue"),
                "SpelExpression#getValue recognized");
        check("EXPRESSION".equals(AgentRuntime.primaryEffectKind(
                        "PROCESS",
                        "org.springframework.expression.spel.standard.SpelExpression",
                        "getValue")),
                "SpEL → effectKind EXPRESSION");
        check(AgentRuntime.isFileWriteSink(
                        "org.apache.commons.io.FileUtils", "copyFile"),
                "FileUtils#copyFile recognized as FILE write");
        check("FILE_WRITE".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "org.apache.commons.io.FileUtils", "writeStringToFile")),
                "FileUtils write → effectKind FILE_WRITE");
    }

    private static void verifyCriticalBudgetRetention() {
        Map<String, String> jdbc = PathDebugDetail.merge(
                Map.of("captureMode", "DATASOURCE_METHOD", "operation", "setJdbcUrl"),
                PathDebugDetail.effectTriggered("SSRF"));
        check(EventWriter.isCriticalEffect("JDBC", jdbc),
                "Hikari setJdbcUrl SSRF survives soft-stop");
        Map<String, String> http = PathDebugDetail.merge(
                Map.of("captureMode", "HTTP_CLIENT_METHOD", "operation", "exchange"),
                PathDebugDetail.effectTriggered("SSRF"));
        check(EventWriter.isCriticalEffect("HTTP_CLIENT", http),
                "RestTemplate SSRF survives soft-stop");
        Map<String, String> expr = PathDebugDetail.merge(
                Map.of("captureMode", "EXPRESSION_EVAL", "operation", "getValue"),
                PathDebugDetail.effectTriggered("EXPRESSION"));
        check(EventWriter.isCriticalEffect("PROCESS", expr),
                "SpEL EXPRESSION survives soft-stop");
    }

    private static void verifyInstrumentedFixture(
            Path agentJar, Path traceDirectory, Class<?> fixtureClass,
            String eventType, String operation, String effectKind, String typeToken)
            throws Exception {
        Files.createDirectories(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, fixtureClass,
                "maxEvents=80,maxBytes=65536,classPrefix=com.aq.fixture", true);
        check(result.exitCode == 0, fixtureClass.getSimpleName() + " failed: " + result.output);
        check(result.output.contains(fixtureClass.getSimpleName() + ": PASS"),
                fixtureClass.getSimpleName() + " did not complete");
        List<String> lines = Files.readAllLines(
                traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME), StandardCharsets.UTF_8);
        String all = String.join("\n", lines);
        check(all.contains("\"eventType\":\"" + eventType + "\""),
                eventType + " event missing for " + fixtureClass.getSimpleName());
        check(all.contains(operation),
                operation + " must be observed for " + fixtureClass.getSimpleName());
        check(all.contains("\"pathDebugKind\":\"EFFECT_TRIGGERED\""),
                "EFFECT_TRIGGERED required for " + fixtureClass.getSimpleName());
        check(all.contains("\"effectKind\":\"" + effectKind + "\""),
                "effectKind " + effectKind + " required for " + fixtureClass.getSimpleName());
        check(all.contains(typeToken),
                typeToken + " must appear in observation for " + fixtureClass.getSimpleName());
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(AgentEffectSurfaceCoverageAcceptanceTest.class);
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
            throw new AssertionError("fixture child JVM timed out: " + fixtureClass.getSimpleName());
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
