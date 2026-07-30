package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.JdkConvergenceFixture;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/**
 * JDK 底层汇聚点：FileOutputStream/Files.write、FileInputStream、
 * ObjectInputStream.readObject、URL.openConnection — 须出细分 effectKind + 诊断字段。
 * 观测 ≠ 确认（确认门禁另测）。
 */
public final class JdkConvergenceAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(30);

    private JdkConvergenceAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        verifyEffectKindSplitAndGating();

        Path work = Path.of("target", "agent-jdk-convergence-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));

        Path traceDir = work.resolve("trace");
        Files.createDirectories(traceDir);
        ProcessResult result = runFixture(agentJar, traceDir, JdkConvergenceFixture.class,
                "maxEvents=120,maxBytes=98304,classPrefix=com.aq.fixture", true);
        check(result.exitCode == 0, "JdkConvergenceFixture failed: " + result.output);
        check(result.output.contains("JdkConvergenceFixture: PASS"),
                "fixture did not complete");

        String all = Files.readString(traceDir.resolve(AgentConfig.TRACE_FILE_NAME),
                StandardCharsets.UTF_8);
        check(all.contains("\"effectKind\":\"FILE_WRITE\""),
                "FILE_WRITE from FileOutputStream/Files.write required");
        check(all.contains("\"effectOp\":\"write\""), "effectOp=write required");
        check(all.contains("\"effectKind\":\"FILE_READ\""),
                "FILE_READ from FileInputStream required when correlation bound");
        check(all.contains("\"effectOp\":\"read\""), "effectOp=read required");
        check(all.contains("\"effectKind\":\"DESERIALIZATION\""),
                "ObjectInputStream.readObject → DESERIALIZATION");
        check(all.contains("\"effectOp\":\"deserialize\""), "effectOp=deserialize required");
        check(all.contains("\"effectKind\":\"SSRF\""),
                "URL.openConnection → SSRF");
        check(all.contains("\"effectOp\":\"connect\""), "effectOp=connect required");
        check(all.contains("pathOrUrl") || all.contains("\"path\""),
                "path/URL summary field required on at least one JDK effect");
        check(all.contains("\"requestBound\":\"true\""),
                "requestBound=true when correlation present");
        check(all.contains("FileOutputStream") || all.contains("java.io.FileOutputStream")
                        || all.contains("java.nio.file.Files"),
                "JDK write owner must appear");
        check(all.contains("ObjectInputStream") || all.contains("java.io.ObjectInputStream"),
                "ObjectInputStream must appear");
        check(all.contains("java.net.URL") || all.contains("HttpURLConnection"),
                "URL/HttpURLConnection must appear");

        System.out.println("JdkConvergenceAcceptanceTest: PASS");
    }

    private static void verifyEffectKindSplitAndGating() {
        check("FILE_WRITE".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "java.io.FileOutputStream", "<init>")),
                "FileOutputStream → FILE_WRITE");
        check("FILE_READ".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "java.io.FileInputStream", "<init>")),
                "FileInputStream → FILE_READ");
        check("FILE_WRITE".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "java.nio.file.Files", "write")),
                "Files.write → FILE_WRITE");
        check("FILE_READ".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "java.nio.file.Files", "readAllBytes")),
                "Files.read* → FILE_READ");
        check("FILE_DELETE".equals(AgentRuntime.primaryEffectKind(
                        "FILE", "java.nio.file.Files", "delete")),
                "Files.delete → FILE_DELETE");
        check("DESERIALIZATION".equals(AgentRuntime.primaryEffectKind(
                        "PROCESS", "java.io.ObjectInputStream", "readObject")),
                "readObject → DESERIALIZATION");
        check("SSRF".equals(AgentRuntime.primaryEffectKind(
                        "HTTP_CLIENT", "java.net.URL", "openConnection")),
                "URL.openConnection → SSRF");
        check("COMMAND".equals(AgentRuntime.primaryEffectKind(
                        "PROCESS", "java.lang.ProcessBuilder", "start")),
                "ProcessBuilder.start → COMMAND");
        check("DNS_LOOKUP".equals(AgentRuntime.primaryEffectKind(
                        "HTTP_CLIENT", "java.net.InetAddress", "getByName")),
                "InetAddress → DNS_LOOKUP (not SSRF confirm signal)");
        check("write".equals(AgentRuntime.effectOp(
                        "java.io.FileOutputStream", "<init>", "FILE_WRITE")),
                "effectOp write");
        check(!AgentRuntime.shouldEmitJdkEffect("FILE_READ", "read", "/tmp/x"),
                "uncorrelated ordinary FILE_READ must be gated");
        check(AgentRuntime.shouldEmitJdkEffect("FILE_READ", "read", "../etc/passwd"),
                "traversal-shaped FILE_READ may emit without correlation");
        check(AgentRuntime.shouldEmitJdkEffect("FILE_WRITE", "write", "/tmp/x"),
                "FILE_WRITE always emits");
        check(!AgentRuntime.shouldEmitJdkEffect("DNS_LOOKUP", "dns", ""),
                "uncorrelated DNS gated");
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(JdkConvergenceAcceptanceTest.class);
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
