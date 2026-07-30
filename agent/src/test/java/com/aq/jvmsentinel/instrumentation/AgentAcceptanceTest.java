package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.AutomaticFixture;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/** End-to-end checks that launch only this repository's harmless fixture in a child JVM. */
public final class AgentAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(20);

    private AgentAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        Path work = Path.of("target", "agent-acceptance-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        if (args.length > 1) throw new IllegalArgumentException("expected at most one packaged agent path");
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));
        check(Files.isRegularFile(agentJar), "agent jar does not exist: " + agentJar);

        verifyCorrelationNesting();
        verifyAutomaticObservation(agentJar, work.resolve("automatic"));
        verifyBranchCoverage(agentJar, work.resolve("coverage"));
        verifyExplicitProbeProvenance(agentJar, work.resolve("explicit"));
        verifyBudgetStop(agentJar, work.resolve("budget"));
        verifyMaxEventsBounds(work.resolve("max-events-bounds"));
        verifyMalformedArgumentsFailClosed(agentJar, work.resolve("malformed"));
        verifyMissingAuthorizationFailsClosed(agentJar, work.resolve("unauthorized"));

        System.out.println("AgentAcceptanceTest: PASS");
    }

    private static void verifyCorrelationNesting() {
        AgentRuntime.bindRequestCorrelation("req-outer");
        AgentRuntime.bindRequestCorrelation("");
        AgentRuntime.releaseRequestCorrelation();
        check("req-outer".equals(AgentRuntime.currentRequestCorrelation()),
                "blank nested HTTP view must not clear outer correlation");
        AgentRuntime.releaseRequestCorrelation();
        check(AgentRuntime.currentRequestCorrelation().isEmpty(),
                "outer HTTP exit must clear request correlation");
    }

    private static void verifyAutomaticObservation(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, AutomaticFixture.class,
                "maxEvents=160,maxBytes=98304,classPrefix=com.aq.fixture", true);
        check(result.exitCode == 0, "instrumented fixture failed: " + result.output);
        check(result.output.contains("AutomaticFixture: PASS"), "automatic fixture did not complete");

        Path trace = traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME);
        List<String> lines = Files.readAllLines(trace, StandardCharsets.UTF_8);
        check(!lines.isEmpty(), "trace must not be empty");
        check(lines.get(0).contains("\"eventType\":\"AGENT_STARTED\""), "premain startup event is missing");
        check(any(lines, "\"eventType\":\"CLASS_LOAD\"")
                        && any(lines, "com.aq.fixture.AutomaticFixture"),
                "fixture class load was not observed");
        for (String type : List.of("HTTP", "HTTP_CLIENT", "FILE", "JDBC", "PROCESS")) {
            check(any(lines, "\"eventType\":\"" + type + "\""), type + " automatic event is missing");
        }
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            check(line.contains("\"schemaVersion\":1"), "schema version is missing");
            check(line.contains("\"sequence\":" + index), "sequence is not contiguous");
            check(line.contains("\"verificationStatus\":\"DYNAMIC_SUSPECTED\""),
                    "agent event must not claim VERIFIED");
            check(line.contains("\"class\":") && line.contains("\"method\":")
                            && line.contains("\"timestamp\":") && line.contains("\"thread\":")
                            && line.contains("\"detail\":"),
                    "required event field is missing");
        }
        String all = String.join("\n", lines);
        check(lines.get(0).contains("\"provenanceKind\":\"RUNTIME_OBSERVED\""),
                "agent-owned event provenance is missing");
        check(lines.stream().filter(line -> List.of("HTTP", "HTTP_CLIENT", "FILE", "JDBC", "PROCESS")
                                .stream().anyMatch(type -> line.contains("\"eventType\":\"" + type + "\"")))
                        .allMatch(line -> line.contains("\"provenanceKind\":\"AGENT_INSTRUMENTED\"")),
                "automatic events must be agent-instrumented");
        check(!any(lines, "\"provenanceKind\":\"APPLICATION_REPORTED\""),
                "automatic fixture must not rely on explicit probes");
        check(any(lines, "\"bootstrapClasses\":\"UNSUPPORTED_FAIL_EXPLICIT\""),
                "bootstrap limitation must be explicit");
        check(!any(lines, "\"eventType\":\"BRANCH_COVERAGE\""),
                "branch coverage must be disabled by default");
    }

    private static void verifyBranchCoverage(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, AutomaticFixture.class,
                "maxEvents=200,maxBytes=131072,classPrefix=com.aq.fixture,"
                        + AgentConfig.COVERAGE_ENABLED_PROPERTY + "=true", true);
        check(result.exitCode == 0, "coverage fixture failed: " + result.output);
        List<String> lines = Files.readAllLines(
                traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME), StandardCharsets.UTF_8);
        List<String> coverage = lines.stream()
                .filter(line -> line.contains("\"eventType\":\"BRANCH_COVERAGE\""))
                .toList();
        check(!coverage.isEmpty(), "branch coverage event is missing");
        check(coverage.stream().allMatch(line ->
                        line.contains("\"provenanceKind\":\"AGENT_INSTRUMENTED\"")),
                "branch coverage provenance must be agent-instrumented");
        check(coverage.stream().anyMatch(line ->
                        line.contains("\"classname\":\"com.aq.fixture.AutomaticFixture\"")
                                && line.contains("\"methodDesc\":\"branchWork(I)I\"")
                                && line.contains("\"hits\":\"")),
                "branch coverage detail shape is missing");
    }

    private static void verifyExplicitProbeProvenance(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, Fixture.class,
                "maxEvents=100,maxBytes=65536", true);
        check(result.exitCode == 0, "explicit fixture failed: " + result.output);
        List<String> lines = Files.readAllLines(
                traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME), StandardCharsets.UTF_8);
        check(lines.stream().filter(line -> line.contains("\"eventType\":\"HTTP\""))
                        .allMatch(line -> line.contains("\"provenanceKind\":\"APPLICATION_REPORTED\"")),
                "explicit probes must remain application-reported");
        String all = String.join("\n", lines);
        check(!all.contains("Bearer raw-token"), "authorization value leaked");
        check(!all.contains("database-password"), "password value leaked");
        check(all.contains("[REDACTED]"), "redaction marker is missing");
        check(!all.contains("line1\\r") && !all.contains("line1\\n"), "control characters were not sanitized");
        check(all.contains("x".repeat(256)) && !all.contains("x".repeat(257)), "detail value limit was not enforced");
        check(!all.contains("\"key14\""), "detail entry count limit was not enforced");
    }

    private static void verifyMaxEventsBounds(Path work) throws Exception {
        Files.createDirectories(work);
        Path authorized = work.resolve("authorized");
        Files.createDirectory(authorized);
        String previousDir = System.getProperty(AgentConfig.TRACE_DIR_PROPERTY);
        String previousAuth = System.getProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY);
        System.setProperty(AgentConfig.TRACE_DIR_PROPERTY, authorized.toString());
        System.setProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY, "true");
        try {
            AgentConfig min = AgentConfig.parse("maxEvents=" + AgentConfig.MIN_MAX_EVENTS + ",maxBytes=4096");
            check(min.maxEvents == AgentConfig.MIN_MAX_EVENTS, "min maxEvents must be accepted");
            AgentConfig max = AgentConfig.parse("maxEvents=" + AgentConfig.MAX_MAX_EVENTS + ",maxBytes=65536");
            check(max.maxEvents == AgentConfig.MAX_MAX_EVENTS, "max maxEvents must be accepted");
            expectOutsideLimits("maxEvents=0,maxBytes=4096");
            expectOutsideLimits("maxEvents=" + (AgentConfig.MAX_MAX_EVENTS + 1) + ",maxBytes=4096");
            // 控制面抬升后的合法上界：500000 不得被误判为越界。
            AgentConfig raisedCap = AgentConfig.parse(
                    "maxEvents=" + AgentConfig.MAX_MAX_EVENTS + ",maxBytes=1048576");
            check(raisedCap.maxEvents == AgentConfig.MAX_MAX_EVENTS,
                    "probe-raised agent max must remain legal");
            check(AgentConfig.MAX_MAX_EVENTS == 500_000,
                    "agent MAX_MAX_EVENTS must stay synced with control-plane AGENT_MAX_EVENTS");
        } finally {
            restoreProperty(AgentConfig.TRACE_DIR_PROPERTY, previousDir);
            restoreProperty(AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY, previousAuth);
        }
    }

    private static void expectOutsideLimits(String arguments) {
        try {
            AgentConfig.parse(arguments);
            throw new AssertionError("expected outside limits for " + arguments);
        } catch (IllegalArgumentException exception) {
            check(exception.getMessage() != null
                            && exception.getMessage().contains("maxEvents is outside limits"),
                    "unexpected parse failure for " + arguments + ": " + exception);
        }
    }

    private static void restoreProperty(String key, String previous) {
        if (previous == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, previous);
        }
    }

    private static void verifyBudgetStop(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, Fixture.class,
                "maxEvents=2,maxBytes=4096", true);
        check(result.exitCode == 0, "budget exhaustion must not crash fixture: " + result.output);
        Path trace = traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME);
        List<String> lines = Files.readAllLines(trace, StandardCharsets.UTF_8);
        // maxEvents=2 keeps two payload events; optional TRACE_BUDGET_EXHAUSTED sentinel is +1.
        check(lines.size() == 2 || lines.size() == 3,
                "event count budget was not enforced; lines=" + lines.size());
        check(lines.size() < 2 || !lines.get(0).contains("TRACE_BUDGET_EXHAUSTED"),
                "budget sentinel must not replace the first payload events");
        if (lines.size() == 3) {
            check(lines.get(2).contains("TRACE_BUDGET_EXHAUSTED"),
                    "third line must be TRACE_BUDGET_EXHAUSTED sentinel");
        }
        check(Files.size(trace) <= 4096, "byte budget was exceeded");
        check(!any(lines, "\"eventType\":\"PROCESS\""), "events continued after budget exhaustion");
    }

    private static void verifyMalformedArgumentsFailClosed(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, Fixture.class,
                "traceDir=C:/host-controlled,maxEvents=10", true);
        check(result.exitCode != 0, "path-bearing agent parameter must be rejected");
        check(!Files.exists(traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME)),
                "malformed configuration must not create trace output");
    }

    private static void verifyMissingAuthorizationFailsClosed(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, Fixture.class, "maxEvents=10", false);
        check(result.exitCode != 0, "missing host authorization must reject agent startup");
        check(!Files.exists(traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME)),
                "unauthorized configuration must not create trace output");
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(AgentAcceptanceTest.class);
        Path byteBuddyClasses = codeSource(net.bytebuddy.agent.builder.AgentBuilder.class);
        List<String> command = new ArrayList<>();
        command.add(java.toString());
        command.add("-D" + AgentConfig.TRACE_DIR_PROPERTY + "=" + traceDirectory);
        command.add("-Dveyrion.fixture.output=" + traceDirectory.resolve("fixture-output.txt"));
        if (authorize) command.add("-D" + AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY + "=true");
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
        attributes.putValue("Can-Redefine-Classes", "false");
        attributes.putValue("Can-Retransform-Classes", "false");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(target), manifest);
             Stream<Path> paths = Files.walk(classes)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                String entryName = classes.relativize(path).toString().replace('\\', '/');
                if (!entryName.endsWith(".class")) continue;
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

    private static boolean any(List<String> lines, String fragment) {
        return lines.stream().anyMatch(line -> line.contains(fragment));
    }

    private static void deleteRecursively(Path path) throws Exception {
        if (!Files.exists(path)) return;
        try (Stream<Path> paths = Files.walk(path)) {
            for (Path entry : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.delete(entry);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record ProcessResult(int exitCode, String output) {
    }

    /**
     * Explicit-probe fixture kept solely to prove that application calls remain APPLICATION_REPORTED.
     */
    public static final class Fixture {
        private Fixture() {
        }

        public static void main(String[] args) {
            Map<String, String> http = new LinkedHashMap<>();
            http.put("Authorization", "Bearer raw-token");
            http.put("note", "line1\r\nline2");
            for (int index = 0; index < 20; index++) {
                http.put("key" + index, index == 0 ? "x".repeat(400) : "value-" + index);
            }
            AgentRuntime.recordHttp(Fixture.class.getName(), "httpProbe", http);
            AgentRuntime.recordFile(Fixture.class.getName(), "fileProbe", Map.of("path", "/sandbox/fixture.txt"));
            AgentRuntime.recordJdbc(Fixture.class.getName(), "jdbcProbe",
                    Map.of("operation", "SELECT", "password", "database-password"));
            AgentRuntime.recordProcess(Fixture.class.getName(), "processProbe",
                    Map.of("intent", "not-executed", "command", "harmless-fixture-marker"));
            System.out.println("Fixture: PASS");
        }
    }
}
