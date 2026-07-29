package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface.DecisionShape;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Load-free harvest of auth/role/permission/license/feature guard type names from an artifact JAR.
 * Drives FORCED_REACHABILITY allowlists; never elevates VERIFIED and never targets sanitizers.
 */
public final class GuardSurfaceCatalog {
    public static final int MAX_SURFACES = 64;
    public static final int MAX_TYPE_NAMES = 48;
    public static final int MAX_TYPE_NAMES_PROPERTY_CHARS = 2048;
    private static final int MAX_OUTER_ENTRIES = 4_000;
    private static final int MAX_NESTED_LIBS = 40;
    private static final int MAX_NESTED_CLASSES_PER_LIB = 800;
    private static final int MAX_NESTED_LIB_BYTES = 8 * 1024 * 1024;

    private GuardSurfaceCatalog() {
    }

    public static List<GuardSurface> harvest(Path artifactPath) {
        if (artifactPath == null || !Files.isRegularFile(artifactPath)) {
            return List.of();
        }
        Map<String, Candidate> byType = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(artifactPath))) {
            ZipEntry entry;
            int scanned = 0;
            int nestedLibs = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < MAX_OUTER_ENTRIES) {
                if (entry.isDirectory()) {
                    continue;
                }
                scanned++;
                String name = entry.getName().replace('\\', '/');
                String lower = name.toLowerCase(Locale.ROOT);
                if (isNestedLibrary(lower)) {
                    if (nestedLibs >= MAX_NESTED_LIBS) {
                        continue;
                    }
                    if (!isAuthFrameworkLibrary(lower)) {
                        continue;
                    }
                    nestedLibs++;
                    byte[] nested = readLimited(zip, MAX_NESTED_LIB_BYTES);
                    scanNestedJar(nested, byType);
                    continue;
                }
                if (!lower.endsWith(".class")) {
                    continue;
                }
                // Skip synthetic/anonymous inners; keep named nested types that look like filters.
                int dollar = lower.lastIndexOf('$');
                if (dollar >= 0) {
                    String after = lower.substring(dollar + 1);
                    if (!after.isEmpty() && Character.isDigit(after.charAt(0))) {
                        continue;
                    }
                }
                String typeName = classNameFromEntry(name);
                consider(typeName, byType);
            }
        } catch (IOException ignored) {
            return List.of();
        }
        return toSurfaces(byType);
    }

    public static List<String> guardRefs(List<GuardSurface> surfaces) {
        if (surfaces == null || surfaces.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> refs = new LinkedHashSet<>();
        for (GuardSurface surface : surfaces) {
            if (surface != null && surface.ref() != null && !surface.ref().isBlank()) {
                refs.add(surface.ref());
            }
        }
        return List.copyOf(refs);
    }

    public static List<String> typeNames(List<GuardSurface> surfaces) {
        if (surfaces == null || surfaces.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (GuardSurface surface : surfaces) {
            if (surface == null) {
                continue;
            }
            for (String typeName : surface.typeNames()) {
                if (typeName != null && !typeName.isBlank()) {
                    names.add(typeName.trim());
                    if (names.size() >= MAX_TYPE_NAMES) {
                        return List.copyOf(names);
                    }
                }
            }
        }
        return List.copyOf(names);
    }

    /** Bounded CSV for {@code -Dveyrion.sandbox.forcedGuardTypeNames}. */
    public static String formatTypeNamesProperty(List<String> typeNames) {
        if (typeNames == null || typeNames.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (String name : typeNames) {
            if (name == null || name.isBlank()) {
                continue;
            }
            String trimmed = name.trim();
            if (!isSafeTypeToken(trimmed)) {
                continue;
            }
            int nextLen = sb.isEmpty() ? trimmed.length() : sb.length() + 1 + trimmed.length();
            if (count >= MAX_TYPE_NAMES || nextLen > MAX_TYPE_NAMES_PROPERTY_CHARS) {
                break;
            }
            if (!sb.isEmpty()) {
                sb.append(',');
            }
            sb.append(trimmed);
            count++;
        }
        return sb.toString();
    }

    private static void scanNestedJar(byte[] nestedJar, Map<String, Candidate> byType) {
        if (nestedJar == null || nestedJar.length == 0) {
            return;
        }
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(nestedJar))) {
            ZipEntry entry;
            int counted = 0;
            while ((entry = zip.getNextEntry()) != null && counted < MAX_NESTED_CLASSES_PER_LIB) {
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName().replace('\\', '/');
                if (!name.toLowerCase(Locale.ROOT).endsWith(".class")) {
                    continue;
                }
                counted++;
                consider(classNameFromEntry(name), byType);
            }
        } catch (IOException ignored) {
            // Nested lib optional.
        }
    }

    private static void consider(String typeName, Map<String, Candidate> byType) {
        if (typeName == null || typeName.isBlank() || byType.containsKey(typeName)) {
            return;
        }
        if (byType.size() >= MAX_SURFACES * 2) {
            return;
        }
        Match match = classify(typeName);
        if (match == null) {
            return;
        }
        byType.put(typeName, new Candidate(match.kind(), match.shape(), typeName, match.simpleName()));
    }

    private static List<GuardSurface> toSurfaces(Map<String, Candidate> byType) {
        Map<String, GuardSurface> byRef = new LinkedHashMap<>();
        for (Candidate candidate : byType.values()) {
            String ref = GuardSurface.refFor(candidate.kind, candidate.simpleName);
            GuardSurface existing = byRef.get(ref);
            if (existing == null) {
                byRef.put(ref, new GuardSurface(
                        ref, candidate.kind, List.of(candidate.typeName), candidate.shape));
            } else {
                LinkedHashSet<String> merged = new LinkedHashSet<>(existing.typeNames());
                merged.add(candidate.typeName);
                DecisionShape shape = existing.decisionShape();
                if (candidate.shape == DecisionShape.ACCESS_CONTROL
                        || existing.decisionShape() == DecisionShape.ACCESS_CONTROL) {
                    shape = DecisionShape.ACCESS_CONTROL;
                } else if (candidate.shape == DecisionShape.FILTER_CHAIN
                        || existing.decisionShape() == DecisionShape.FILTER_CHAIN) {
                    shape = DecisionShape.FILTER_CHAIN;
                }
                byRef.put(ref, new GuardSurface(ref, candidate.kind, List.copyOf(merged), shape));
            }
            if (byRef.size() >= MAX_SURFACES) {
                break;
            }
        }
        return List.copyOf(byRef.values());
    }

    private static Match classify(String typeName) {
        String binary = typeName.replace('/', '.');
        String lower = binary.toLowerCase(Locale.ROOT);
        String simple = simpleName(binary).toLowerCase(Locale.ROOT);
        if (isExcluded(simple, lower)) {
            return null;
        }
        ForcedGuardKind kind = kindFor(simple, lower);
        if (kind == null) {
            return null;
        }
        DecisionShape shape = shapeFor(simple, lower);
        return new Match(kind, shape, simpleName(binary));
    }

    private static ForcedGuardKind kindFor(String simple, String lower) {
        if (simple.contains("license") || lower.contains("licensefilter")) {
            return ForcedGuardKind.LICENSE;
        }
        if (simple.contains("feature") && simple.contains("filter")) {
            return ForcedGuardKind.FEATURE;
        }
        if (simple.contains("permission") || lower.contains(".authz.")
                || simple.contains("rolesauthorization") || simple.contains("permissionsauthorization")) {
            return ForcedGuardKind.PERMISSION;
        }
        if (simple.contains("role") && (simple.contains("filter") || simple.contains("authorization"))) {
            return ForcedGuardKind.ROLE;
        }
        if (lower.startsWith("org.apache.shiro.web.filter.authc.")
                || lower.startsWith("org.apache.shiro.web.filter.authz.")
                || lower.startsWith("org.springframework.security.web.")
                || simple.equals("loginfilter")
                || simple.contains("authfilter")
                || simple.contains("authenticationfilter")
                || simple.contains("authorizationfilter")
                || simple.contains("userfilter")
                || simple.contains("jwtfilter")
                || simple.contains("tokenfilter")
                || simple.contains("bearerfilter")
                || simple.contains("bearertoken")
                || simple.contains("accesscontrol")
                || simple.contains("filterchainproxy")
                || simple.contains("filtersecurityinterceptor")
                || simple.contains("exceptiontranslationfilter")
                || simple.contains("usernamepasswordauthenticationfilter")
                || simple.contains("basicauthenticationfilter")
                || simple.contains("preauth")
                || simple.contains("securefilter")
                || (simple.contains("auth") && simple.endsWith("filter"))) {
            return ForcedGuardKind.AUTH;
        }
        return null;
    }

    private static DecisionShape shapeFor(String simple, String lower) {
        if (simple.contains("accesscontrol")
                || lower.contains("accesscontrolfilter")
                || lower.startsWith("org.apache.shiro.web.filter.authc.")
                || lower.startsWith("org.apache.shiro.web.filter.authz.")) {
            return DecisionShape.ACCESS_CONTROL;
        }
        if (simple.endsWith("filter") || lower.contains("filterchainproxy")
                || lower.contains("filtersecurityinterceptor")) {
            return DecisionShape.FILTER_CHAIN;
        }
        return DecisionShape.HEURISTIC;
    }

    private static boolean isExcluded(String simple, String lower) {
        if (simple.contains("xss") || simple.contains("sqlfilter") || simple.contains("sqlinjection")
                || simple.contains("sanitiz") || simple.contains("csrf")
                || simple.contains("characterencoding") || simple.contains("corsfilter")
                || simple.contains("hiddenhttpmethod") || simple.contains("requestcontext")
                || simple.contains("formcontent") || simple.contains("forwardedheader")
                || simple.contains("resourcerequest") || simple.contains("metrictag")
                || simple.contains("httptrace") || simple.contains("websitemesh")) {
            return true;
        }
        // Container / infra bases — never force the outer chain binder.
        if (simple.equals("abstractshirofilter")
                || simple.equals("springshirofilter")
                || simple.equals("pathmatchingfilter")
                || simple.equals("advicefilter")
                || simple.equals("onceperrequestfilter")
                || simple.equals("genericfilterbean")
                || lower.contains("shirofilterfactorybean$springshirofilter")
                || lower.endsWith(".abstractshirofilter")) {
            return true;
        }
        return ForcedGuardKind.isForbiddenForceTarget(simple)
                || ForcedGuardKind.isForbiddenForceTarget(lower);
    }

    private static boolean isNestedLibrary(String lowerPath) {
        return (lowerPath.startsWith("boot-inf/lib/") || lowerPath.startsWith("web-inf/lib/"))
                && lowerPath.endsWith(".jar");
    }

    private static boolean isAuthFrameworkLibrary(String lowerPath) {
        String file = lowerPath;
        int slash = lowerPath.lastIndexOf('/');
        if (slash >= 0) {
            file = lowerPath.substring(slash + 1);
        }
        return file.contains("shiro-web")
                || file.contains("shiro-spring")
                || file.contains("spring-security-web")
                || file.contains("spring-security-config")
                || file.contains("spring-security-core");
    }

    private static String classNameFromEntry(String entryName) {
        String normalized = entryName.replace('\\', '/');
        if (normalized.startsWith("BOOT-INF/classes/")) {
            normalized = normalized.substring("BOOT-INF/classes/".length());
        } else if (normalized.startsWith("WEB-INF/classes/")) {
            normalized = normalized.substring("WEB-INF/classes/".length());
        }
        if (normalized.toLowerCase(Locale.ROOT).endsWith(".class")) {
            normalized = normalized.substring(0, normalized.length() - 6);
        }
        return normalized.replace('/', '.');
    }

    private static String simpleName(String binary) {
        int dot = binary.lastIndexOf('.');
        return dot >= 0 && dot + 1 < binary.length() ? binary.substring(dot + 1) : binary;
    }

    private static boolean isSafeTypeToken(String token) {
        if (token.length() > 200) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '$')) {
                return false;
            }
        }
        return token.indexOf('.') >= 0 || Character.isLetter(token.charAt(0));
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

    private record Candidate(ForcedGuardKind kind, DecisionShape shape, String typeName, String simpleName) {
    }

    private record Match(ForcedGuardKind kind, DecisionShape shape, String simpleName) {
    }
}
