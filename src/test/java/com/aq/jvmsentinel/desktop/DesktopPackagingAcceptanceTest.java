package com.aq.jvmsentinel.desktop;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.SchemaContractAcceptanceTest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * P2 SCAFFOLDING: desktop-jlink.ps1 -DryRun success path with a fake JDK that provides jlink.
 */
public final class DesktopPackagingAcceptanceTest {
    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        Path root = SchemaContractAcceptanceTest.projectRoot();
        Path script = root.resolve("scripts/desktop-jlink.ps1");
        Path doc = root.resolve("docs/desktop/DESKTOP_PACKAGING.md");
        check(Files.isRegularFile(script), "scripts/desktop-jlink.ps1 exists");
        check(Files.isRegularFile(doc), "docs/desktop/DESKTOP_PACKAGING.md exists");
        String docText = Files.readString(doc, StandardCharsets.UTF_8);
        check(docText.toLowerCase(Locale.ROOT).contains("scaffolding"),
                "desktop doc marks SCAFFOLDING");
        check(docText.contains("jlink") && docText.contains("jpackage"),
                "desktop doc mentions jlink+jpackage");

        Path fakeJdk = Files.createTempDirectory("veyrion-desktop-jdk-");
        try {
            Path bin = Files.createDirectories(fakeJdk.resolve("bin"));
            Path jlink = bin.resolve("jlink.exe");
            Files.writeString(jlink, "@echo off\r\n", StandardCharsets.UTF_8);

            List<String> command = List.of(
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    script.toAbsolutePath().toString(),
                    "-DryRun");
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(root.toFile());
            pb.redirectErrorStream(true);
            pb.environment().put("JAVA_HOME", fakeJdk.toAbsolutePath().toString());
            Process process = pb.start();
            List<String> lines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            check(finished, "desktop-jlink DryRun terminated");
            int code = process.exitValue();
            String joined = String.join("\n", lines);
            check(code == 0, "DryRun exit 0, got " + code + " output:\n" + joined);
            check(joined.contains("DESKTOP_JLINK_DRY_RUN_OK"),
                    "DryRun prints DESKTOP_JLINK_DRY_RUN_OK");
        } finally {
            deleteRecursively(fakeJdk);
        }
        System.out.println("DesktopPackagingAcceptanceTest: PASS");
    }

    private static void deleteRecursively(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            List<Path> paths = walk.sorted((a, b) -> b.compareTo(a)).toList();
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}
