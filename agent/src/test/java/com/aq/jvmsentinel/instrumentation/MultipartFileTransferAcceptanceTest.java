package com.aq.jvmsentinel.instrumentation;

import com.aq.fixture.MultipartFileTransferFixture;

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
 * kvf-shaped multipart upload: MultipartFile#transferTo must emit FILE +
 * EFFECT_TRIGGERED (not only Files/FileOutputStream call sites inside Spring).
 */
public final class MultipartFileTransferAcceptanceTest {
    private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(25);

    private MultipartFileTransferAcceptanceTest() {
    }

    public static void main(String[] args) throws Exception {
        verifyEffectKindMapping();
        verifyCriticalBudgetRetention();

        Path work = Path.of("target", "multipart-transfer-work").toAbsolutePath().normalize();
        deleteRecursively(work);
        Files.createDirectories(work);
        Path agentJar = args.length == 1
                ? Path.of(args[0]).toAbsolutePath()
                : createAgentJar(work.resolve("veyrion-agent-test.jar"));

        verifyInstrumentedFixture(agentJar, work.resolve("fixture"));
        System.out.println("MultipartFileTransferAcceptanceTest: PASS");
    }

    private static void verifyEffectKindMapping() {
        check(AgentRuntime.isMultipartFileWriteSink(
                        "org.springframework.web.multipart.MultipartFile", "transferTo"),
                "interface MultipartFile#transferTo recognized");
        check(AgentRuntime.isMultipartFileWriteSink(
                        "org.springframework.web.multipart.support.StandardMultipartFile",
                        "transferTo"),
                "StandardMultipartFile#transferTo recognized");
        check("FILE_WRITE".equals(AgentRuntime.primaryEffectKind(
                        "FILE",
                        "org.springframework.web.multipart.MultipartFile",
                        "transferTo")),
                "primaryEffectKind FILE_WRITE for transferTo");
        check(!AgentRuntime.isMultipartFileWriteSink(
                        "org.springframework.web.multipart.MultipartFile", "getBytes"),
                "getBytes must not be FILE write sink");
    }

    private static void verifyCriticalBudgetRetention() {
        Map<String, String> detail = PathDebugDetail.merge(
                Map.of(
                        "captureMode", "MULTIPART_TRANSFER",
                        "operation", "transferTo"),
                PathDebugDetail.effectTriggered("FILE_WRITE"));
        check(EventWriter.isCriticalEffect("FILE", detail),
                "MULTIPART_TRANSFER FILE_WRITE effect survives maxEvents soft-stop");
    }

    private static void verifyInstrumentedFixture(Path agentJar, Path traceDirectory)
            throws Exception {
        Files.createDirectory(traceDirectory);
        ProcessResult result = runFixture(agentJar, traceDirectory, MultipartFileTransferFixture.class,
                "maxEvents=80,maxBytes=65536,classPrefix=com.aq.fixture", true);
        check(result.exitCode == 0, "fixture failed: " + result.output);
        check(result.output.contains("MultipartFileTransferFixture: PASS"),
                "fixture did not complete");
        List<String> lines = Files.readAllLines(
                traceDirectory.resolve(AgentConfig.TRACE_FILE_NAME), StandardCharsets.UTF_8);
        String all = String.join("\n", lines);
        check(all.contains("\"eventType\":\"FILE\""), "FILE event missing");
        check(all.contains("transferTo"), "transferTo operation must be observed");
        check(all.contains("\"pathDebugKind\":\"EFFECT_TRIGGERED\""),
                "EFFECT_TRIGGERED marker required for H4");
        check(all.contains("\"effectKind\":\"FILE_WRITE\""),
                "effectKind FILE_WRITE required for write confirmation");
        check(all.contains("MultipartFile") || all.contains("MULTIPART_TRANSFER")
                        || all.contains("FileUploadKit"),
                "multipart transfer surface must appear in observation");
    }

    private static ProcessResult runFixture(Path agentJar, Path traceDirectory, Class<?> fixtureClass,
                                            String agentArguments, boolean authorize) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java");
        Path mainClasses = codeSource(VeyrionAgent.class);
        Path testClasses = codeSource(MultipartFileTransferAcceptanceTest.class);
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
