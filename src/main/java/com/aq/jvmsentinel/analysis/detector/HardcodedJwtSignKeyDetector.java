package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 已 surface 的 artifact class 或 nested framework JAR 中嵌入 well-known/hardcoded JWT signing key
 *（如 Blade {@code JwtProperties} 默认）。仅 CONFIG family — 永不
 * 提升 DYNAMIC_CONFIRMED / VERIFIED。
 */
public final class HardcodedJwtSignKeyDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROP_HARDCODED_JWT_SIGN_KEY = "HARDCODED_JWT_SIGN_KEY";

    private static final int MAX_OUTER = 4_000;
    private static final int MAX_NESTED_LIBS = 48;
    private static final int MAX_NESTED_BYTES = 6 * 1024 * 1024;
    private static final int MAX_ENTRY_BYTES = 96 * 1024;

    @Override
    public String id() {
        return DetectorIds.HARDCODED_JWT_SIGN_KEY;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.CONFIG;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int ordinal = 0;
        List<AuthCodeQueryService.WellKnownKey> dictionary =
                FrameworkAdapterRegistry.wellKnownJwtSigningDictionaries();
        if (dictionary.isEmpty()) {
            return List.of();
        }
        if (context.artifactPath() != null) {
            for (Hit hit : scanArtifact(context.artifactPath(), dictionary)) {
                String source = truncate(hit.sourcePath() + " alias=" + hit.alias());
                String key = PROP_HARDCODED_JWT_SIGN_KEY + "|" + source.toLowerCase(Locale.ROOT);
                if (!seen.add(key)) {
                    continue;
                }
                ordinal++;
                out.add(hypothesis(context, ordinal, source, "jwt-default-or-hardcoded-sign-key"));
            }
        }
        if (out.isEmpty()) {
            for (String line : context.configurationLines()) {
                if (line == null || line.isBlank()) continue;
                for (AuthCodeQueryService.WellKnownKey known : dictionary) {
                    if (!line.contains(known.value())) continue;
                    String source = "config:" + truncate(line) + " alias=" + known.alias();
                    String key = PROP_HARDCODED_JWT_SIGN_KEY + "|" + source.toLowerCase(Locale.ROOT);
                    if (!seen.add(key)) continue;
                    ordinal++;
                    out.add(hypothesis(context, ordinal, source, "jwt-default-or-hardcoded-sign-key"));
                }
            }
        }
        return List.copyOf(out);
    }

    static List<Hit> scanArtifact(Path jar, List<AuthCodeQueryService.WellKnownKey> dictionary) {
        if (jar == null || !Files.isRegularFile(jar) || dictionary == null || dictionary.isEmpty()) {
            return List.of();
        }
        List<Hit> hits = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry entry;
            int scanned = 0;
            int nestedLibs = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < MAX_OUTER) {
                if (entry.isDirectory()) continue;
                scanned++;
                String name = entry.getName().replace('\\', '/');
                String lower = name.toLowerCase(Locale.ROOT);
                if (isNestedLibrary(lower)) {
                    if (nestedLibs >= MAX_NESTED_LIBS || !isJwtAuthLibrary(lower)) {
                        continue;
                    }
                    nestedLibs++;
                    byte[] nested = readLimited(zip, MAX_NESTED_BYTES);
                    scanNestedJar(nested, "BOOT-INF/lib/" + fileName(lower), dictionary, hits, seen);
                    continue;
                }
                if (!(lower.endsWith(".class") || lower.endsWith(".yml") || lower.endsWith(".yaml")
                        || lower.endsWith(".properties") || lower.endsWith(".xml"))) {
                    continue;
                }
                if (entry.getSize() > MAX_ENTRY_BYTES) continue;
                byte[] bytes = readLimited(zip, MAX_ENTRY_BYTES);
                considerBytes(name, bytes, dictionary, hits, seen);
            }
        } catch (IOException ignored) {
            return List.copyOf(hits);
        }
        return List.copyOf(hits);
    }

    private static void scanNestedJar(
            byte[] nestedJar,
            String nestLabel,
            List<AuthCodeQueryService.WellKnownKey> dictionary,
            List<Hit> hits,
            Set<String> seen) {
        if (nestedJar == null || nestedJar.length == 0) return;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(nestedJar))) {
            ZipEntry entry;
            int counted = 0;
            while ((entry = zip.getNextEntry()) != null && counted < 600) {
                if (entry.isDirectory()) continue;
                String name = entry.getName().replace('\\', '/');
                String lower = name.toLowerCase(Locale.ROOT);
                if (!(lower.endsWith(".class") || lower.endsWith(".yml") || lower.endsWith(".yaml")
                        || lower.endsWith(".properties"))) {
                    continue;
                }
                counted++;
                byte[] bytes = readLimited(zip, MAX_ENTRY_BYTES);
                considerBytes(nestLabel + "!" + name, bytes, dictionary, hits, seen);
            }
        } catch (IOException ignored) {
            // Nested 可选。
        }
    }

    private static void considerBytes(
            String sourcePath,
            byte[] bytes,
            List<AuthCodeQueryService.WellKnownKey> dictionary,
            List<Hit> hits,
            Set<String> seen) {
        if (bytes == null || bytes.length == 0) return;
        String latin = new String(bytes, StandardCharsets.ISO_8859_1);
        for (AuthCodeQueryService.WellKnownKey known : dictionary) {
            if (known == null || !known.jwtSigning() || known.value() == null) continue;
            if (!latin.contains(known.value())) continue;
            String dedupe = known.alias() + "|" + sourcePath.toLowerCase(Locale.ROOT);
            if (!seen.add(dedupe)) continue;
            hits.add(new Hit(known.alias(), sourcePath));
            return;
        }
    }

    private static SecurityHypothesis hypothesis(
            DetectorContext context, int ordinal, String source, String effect) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-jwt-" + context.scanId() + "-" + ordinal,
                context.scanId(),
                PROP_HARDCODED_JWT_SIGN_KEY,
                HypothesisFamily.CONFIG,
                HypothesisLifecycle.CANDIDATE,
                DetectorIds.HARDCODED_JWT_SIGN_KEY + "/" + VERSION,
                List.of(),
                List.of(),
                List.of(),
                source,
                effect);
    }

    private static boolean isNestedLibrary(String lowerPath) {
        return (lowerPath.startsWith("boot-inf/lib/") || lowerPath.startsWith("web-inf/lib/"))
                && lowerPath.endsWith(".jar");
    }

    private static boolean isJwtAuthLibrary(String lowerPath) {
        String file = fileName(lowerPath);
        return file.contains("blade-starter-jwt")
                || file.contains("blade-core-secure")
                || file.contains("blade-core-tool")
                || file.contains("jjwt")
                || file.contains("nimbus-jose")
                || file.contains("java-jwt");
    }

    private static String fileName(String lowerPath) {
        int slash = lowerPath.lastIndexOf('/');
        return slash >= 0 ? lowerPath.substring(slash + 1) : lowerPath;
    }

    private static String truncate(String value) {
        if (value == null) return "";
        String trimmed = value.trim();
        return trimmed.length() <= 180 ? trimmed : trimmed.substring(0, 180);
    }

    private static byte[] readLimited(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8_192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (total + read > maxBytes) {
                out.write(buffer, 0, maxBytes - total);
                break;
            }
            out.write(buffer, 0, read);
            total += read;
        }
        return out.toByteArray();
    }

    record Hit(String alias, String sourcePath) {
    }
}
