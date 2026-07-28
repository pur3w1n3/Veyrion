package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.*;
import com.aq.jvmsentinel.artifact.*;
import com.aq.jvmsentinel.event.*;
import com.aq.jvmsentinel.model.*;
import com.aq.jvmsentinel.policy.*;

import java.nio.file.*;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Dependency-free executable acceptance checks; run after test compilation with java -ea. */
public final class AcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("jvm-verifier-test");
        Path classFile = root.resolve("UploadController.class");
        Files.writeString(classFile, "test artifact");
        ArtifactRegistry registry = new ArtifactRegistry(root, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));
        ArtifactDescriptor descriptor = registry.register(classFile);
        check(descriptor.staticOnly(), "CLASS must be static-only");
        check(descriptor.sha256().equals(ArtifactRegistry.sha256(classFile)), "SHA-256 mismatch");
        check(registry.register(classFile) == descriptor, "same digest must be idempotent");
        Files.writeString(classFile, "changed");
        expect(ArtifactValidationException.class, () -> registry.verifyUnchanged(descriptor));
        Files.writeString(classFile, "test artifact");
        expect(ArtifactValidationException.class, () -> registry.register(root.resolve("../outside.jar")));
        Path invalidJar = root.resolve("invalid.jar");
        Files.writeString(invalidJar, "not a zip");
        expect(ArtifactValidationException.class, () -> registry.register(invalidJar));
        Path archive = root.resolve("many.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
            output.putNextEntry(new ZipEntry("A.class"));
            output.write(1);
            output.closeEntry();
            output.putNextEntry(new ZipEntry("B.class"));
            output.write(1);
            output.closeEntry();
        }
        expect(ArtifactValidationException.class, () -> new ArtifactRegistry(root, Clock.systemUTC(), 1024, 1, 1024).register(archive));

        ScanPolicy safeDefault = ScanPolicy.safeDefault();
        check(safeDefault.maxMemoryBytes() == 2L * 1024 * 1024 * 1024,
                "safe scan policy defaults memory to 2048 MiB");
        expect(PolicyViolationException.class, () -> PolicyValidator.requireStartAllowed(safeDefault));
        ScanPolicy policy = new ScanPolicy(true, NetworkMode.DENY, DangerousActionMode.DRY_RUN, List.of(), 1, 1, 1);
        PolicyValidator.requireStartAllowed(policy);

        PreAnalysisResult result = new PreAnalysisService().analyze(new PreAnalysisInput(descriptor,
                List.of("com.example.UploadController", "com.example.FileService", "com.example.ProcessBuilderRunner", "com.example.OrderRepository"),
                List.of("spring.datasource.url=jdbc:h2:mem:test", "spring.datasource.password=super-secret", "password: yaml-secret")));
        check(!result.entryCatalog().entries().isEmpty(), "controller should produce entry inference");
        check(result.entryCatalog().entries().get(0).status() == VerificationStatus.STATIC_INFERRED, "entry status");
        check(result.entryCatalog().entries().get(0).confidence() < 1.0, "inference confidence must not be fact confidence");
        check(result.dependencyMap().accesses().stream().anyMatch(d -> d.mode().equals("MOCK")), "dependency mode must be MOCK");
        check(result.entryCatalog().evidence().stream().anyMatch(e -> e.kind() == ProvenanceKind.FACT), "config fact missing");
        check(result.entryCatalog().evidence().stream().noneMatch(e -> e.summary().contains("super-secret")), "configuration secret leaked");
        check(result.entryCatalog().evidence().stream().noneMatch(e -> e.summary().contains("yaml-secret")), "YAML configuration secret leaked");

        VersionedEvent event = EventFactory.create("Test", 1, new IdempotencyKey("scan", "same"), "{}", Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));
        check(event.schemaVersion() == 1 && event.idempotencyKey().value().equals("same"), "event contract");
        VersionedEvent scoped = EventFactory.create("Scoped", 1,
                new EventContext("project", descriptor.sha256(), "scan", "task"),
                new IdempotencyKey("task", "same"), "{}", Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));
        check(scoped.context() != null && scoped.context().artifactDigest().equals(descriptor.sha256()), "event scope");
        System.out.println("AcceptanceTest: PASS");
    }

    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable runnable) throws Exception {
        try { runnable.run(); } catch (Throwable actual) { if (type.isInstance(actual)) return; throw actual; }
        throw new AssertionError("expected " + type.getSimpleName());
    }
    @FunctionalInterface interface ThrowingRunnable { void run() throws Exception; }
}
