package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.AutomaticFixture;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/** P0-21: path-debug sensor detail markers in agent JSONL output. */
public final class PathDebugSensorAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(25);

    private PathDebugSensorAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        Path work = Path.of("target", "path-debug-sensor-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));

        verifyPathDebugMarkers(agentJar, work.resolve("sensor"));
        verifyObserveFailMode(agentJar, work.resolve("observe-fail"));
        verifyNonDockerPostureDisabled();
        System.out.println("PathDebugSensorAcceptanceTest: PASS");
    }

    private static void verifyPathDebugMarkers(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, AutomaticFixture.class,
                "maxEvents=200,maxBytes=131072,classPrefix=com.aq.fixture", true, null);
        check(result.exitCode == 0, "fixture failed: " + result.output);
        List<String> lines = Files.readAllLines(traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME),
                StandardCharsets.UTF_8);
        String all = String.join("\n", lines);
        check(all.contains("\"pathDebugKind\":\"METHOD_HOP\""), "METHOD_HOP marker present");
        check(all.contains("\"pathDebugKind\":\"EFFECT_TRIGGERED\""), "EFFECT_TRIGGERED marker present");
        check(all.contains("\"effectKind\":\"PROCESS\"")
                        || all.contains("\"effectKind\":\"COMMAND\"")
                        || all.contains("\"effectKind\":\"FILE\"")
                        || all.contains("\"effectKind\":\"FILE_WRITE\"")
                        || all.contains("\"effectKind\":\"SSRF\""),
                "effectKind detail present");
        check(all.contains("\"effectKind\":\"SSRF\"") || all.contains("\"eventType\":\"HTTP_CLIENT\""),
                "HTTP client / SSRF observation retained under whitelist eventTypes");
    }

    private static void verifyObserveFailMode(Path agentJar, Path traceDirectory) throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, AutomaticFixture.class,
                "maxEvents=200,maxBytes=131072,classPrefix=com.aq.fixture,"
                        + AgentConfig.WORLD_PACK_DEPENDENCY_MODE_PROPERTY + "=OBSERVE_FAIL",
                true, Map.of(
                        AgentConfig.WORLD_PACK_DEPENDENCY_MODE_PROPERTY, "OBSERVE_FAIL",
                        "veyrion.sandbox.dependencyMock", "false"));
        List<String> lines = Files.readAllLines(traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME),
                StandardCharsets.UTF_8);
        check(lines.stream().anyMatch(line -> line.contains("\"pathDebugKind\":\"DEPENDENCY_FAILURE\"")
                        || line.contains("\"dependencyMode\":\"OBSERVE_FAIL\"")),
                "OBSERVE_FAIL records dependency failure before SQLException exit");
        check(result.exitCode != 0 || result.output.contains("SQLException"),
                "OBSERVE_FAIL JDBC path fails closed (non-zero exit or SQLException)");
    }

    private static void verifyNonDockerPostureDisabled() {
        // Host test JVM must not enable sandbox posture without veyrion.sandbox.docker=true.
        check(!FrameworkBoundaryAdapter.sandboxEnabled(), "host JVM must not enable sandbox posture");
        check("UNAUTH".equals(FrameworkBoundaryAdapter.resolvePosture("FORCED_REACHABILITY")),
                "non-docker forced posture header ignored when docker flag absent");
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize,
                                            java.util.Map<String, String> extraProps) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(PathDebugSensorAcceptanceTest.class);
        Path byteBuddyClasses = codeSource(net.bytebuddy.agent.builder.AgentBuilder.class);
        List<String> command = new ArrayList<>();
        command.add(java.toString());
        command.add("-D" + AgentConfig.TRACE_DIR_PROPERTY + "=" + traceDirectory);
        command.add("-Dveyrion.fixture.output=" + traceDirectory.resolve("fixture-output.txt"));
        if (extraProps != null) {
            for (var entry : extraProps.entrySet()) {
                command.add("-D" + entry.getKey() + "=" + entry.getValue());
            }
        }
        if (authorize) {
            command.add("-D" + AgentConfig.TRACE_DIR_AUTHORIZED_PROPERTY + "=true");
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
}
