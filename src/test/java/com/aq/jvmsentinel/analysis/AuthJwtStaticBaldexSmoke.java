package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.artifact.ArtifactRegistry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

/**
 * Optional real-artifact smoke: set VEYRION_BALDEX_JAR to a SpringBlade/baldex executable JAR.
 * Skips cleanly when unset so default CI does not require the sample.
 */
public final class AuthJwtStaticBaldexSmoke {
    private AuthJwtStaticBaldexSmoke() {
    }

    public static void main(String[] args) throws Exception {
        String configured = System.getenv("VEYRION_BALDEX_JAR");
        if (configured == null || configured.isBlank()) {
            System.out.println("AuthJwtStaticBaldexSmoke: SKIP (VEYRION_BALDEX_JAR unset)");
            return;
        }
        Path jar = Path.of(configured).toAbsolutePath().normalize();
        if (!Files.isRegularFile(jar)) {
            throw new AssertionError("VEYRION_BALDEX_JAR is not a regular file: " + jar);
        }
        Path root = Path.of(".").toAbsolutePath().normalize();
        while (root != null && !Files.isRegularFile(root.resolve("PROJECT_MEMORY.md"))) {
            root = root.getParent();
        }
        if (root == null) {
            throw new AssertionError("could not locate workspace root");
        }
        ArtifactRegistry registry = new ArtifactRegistry(root);
        var result = new PreAnalysisService().analyze(ArtifactMetadataReader.read(registry.register(jar)));
        var cats = result.sinkCatalog().sinks().stream()
                .collect(Collectors.groupingBy(sink -> sink.category(), Collectors.counting()));
        System.out.println("entries=" + result.entryCatalog().entries().size());
        System.out.println("sinkCategories=" + cats);
        long authRelated = result.sinkCatalog().sinks().stream()
                .filter(sink -> sink.category().equals("JWT")
                        || sink.category().equals("AUTH")
                        || sink.category().equals("AUTH_GAP"))
                .count();
        System.out.println("authRelatedSinks=" + authRelated);
        result.sinkCatalog().sinks().stream()
                .filter(sink -> sink.category().equals("JWT")
                        || sink.category().equals("AUTH")
                        || sink.category().equals("AUTH_GAP"))
                .limit(16)
                .forEach(sink -> System.out.println(sink.category() + " | " + sink.symbol()));
        if (authRelated < 1) {
            throw new AssertionError("expected JWT/AUTH/AUTH_GAP static signals on baldex-class JAR");
        }
        if (result.sinkCatalog().sinks().stream()
                .anyMatch(sink -> sink.status().name().equals("VERIFIED"))) {
            throw new AssertionError("static auth signals must never be VERIFIED");
        }
        System.out.println("AuthJwtStaticBaldexSmoke: PASS");
    }
}
