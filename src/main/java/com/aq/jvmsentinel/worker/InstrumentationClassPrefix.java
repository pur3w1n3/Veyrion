package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 解析 Agent {@code classPrefix}，使 FORCED/COVERAGE PathTrace 能记录
 * Controller → Service → Util → Repository 跳转，而非仅主入口的叶包。
 *
 * <p>此前 Control Plane 使用 {@code declaringClass} 的即时包
 *（如 {@code com.app.common.controller}），排除了同级 {@code .service}/
 * {@code .mapper} 类型，导致 FORCED 下 METHOD_HOP / EFFECT 证据不足。</p>
 */
public final class InstrumentationClassPrefix {
    private static final Set<String> TERMINAL_LAYERS = Set.of(
            "controller", "controllers", "web", "api", "rest", "resource", "resources",
            "endpoint", "endpoints", "servlet", "servlets");
    private static final Set<String> TOO_BROAD = Set.of(
            "com", "org", "net", "io", "cn", "edu", "gov", "jp", "de", "uk");

    private InstrumentationClassPrefix() {
    }

    public static String resolve(ApiDtos.EntryDto primary, List<ApiDtos.EntryDto> entries) {
        Objects.requireNonNull(primary, "primary");
        List<String> packages = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (ApiDtos.EntryDto entry : entries == null ? List.<ApiDtos.EntryDto>of() : entries) {
            if (entry == null) continue;
            String pkg = packageOf(entry.declaringClass());
            if (!pkg.isBlank() && seen.add(pkg)) {
                packages.add(pkg);
            }
        }
        String primaryPkg = packageOf(primary.declaringClass());
        if (!primaryPkg.isBlank() && seen.add(primaryPkg)) {
            packages.add(0, primaryPkg);
        }
        String common = longestCommonPackagePrefix(packages);
        if (isUsable(common)) {
            return stripTerminalLayer(common);
        }
        return broadenPrimary(primaryPkg);
    }

    static String packageOf(String declaringClass) {
        if (declaringClass == null || declaringClass.isBlank()) return "";
        String name = declaringClass.trim();
        int slash = name.indexOf('/');
        if (slash >= 0) name = name.replace('/', '.');
        int dollar = name.indexOf('$');
        if (dollar >= 0) name = name.substring(0, dollar);
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : "";
    }

    static String longestCommonPackagePrefix(List<String> packages) {
        if (packages == null || packages.isEmpty()) return "";
        String[] first = packages.get(0).split("\\.");
        int depth = first.length;
        for (int i = 1; i < packages.size(); i++) {
            String[] parts = packages.get(i).split("\\.");
            int shared = 0;
            while (shared < depth && shared < parts.length
                    && first[shared].equals(parts[shared])) {
                shared++;
            }
            depth = shared;
            if (depth == 0) return "";
        }
        if (depth <= 0) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            if (i > 0) out.append('.');
            out.append(first[i]);
        }
        return out.toString();
    }

    static boolean isUsable(String prefix) {
        if (prefix == null || prefix.isBlank()) return false;
        String[] parts = prefix.split("\\.");
        if (parts.length < 2) return false;
        if (parts.length == 2 && TOO_BROAD.contains(parts[0].toLowerCase(Locale.ROOT))) {
            // 例如 com.kalvin 可接受（2 段 vendor）；上文已拒绝单独的 com
            return !parts[1].isBlank();
        }
        return !TOO_BROAD.contains(prefix.toLowerCase(Locale.ROOT));
    }

    static String stripTerminalLayer(String prefix) {
        if (prefix == null || prefix.isBlank()) return "";
        String[] parts = prefix.split("\\.");
        if (parts.length < 3) return prefix;
        String last = parts[parts.length - 1].toLowerCase(Locale.ROOT);
        if (!TERMINAL_LAYERS.contains(last)) return prefix;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length - 1; i++) {
            if (i > 0) out.append('.');
            out.append(parts[i]);
        }
        String stripped = out.toString();
        return isUsable(stripped) ? stripped : prefix;
    }

    static String broadenPrimary(String primaryPackage) {
        if (primaryPackage == null || primaryPackage.isBlank()) return "";
        String stripped = stripTerminalLayer(primaryPackage);
        String[] parts = stripped.split("\\.");
        // 优先应用根：至少保留 vendor.product（2 段），最多 4 段。
        int keep = Math.min(Math.max(parts.length, 0), 4);
        if (parts.length >= 3) {
            keep = Math.min(3, parts.length); // com.kalvin.kvf
        }
        if (keep < 2) return stripped;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < keep; i++) {
            if (i > 0) out.append('.');
            out.append(parts[i]);
        }
        String candidate = out.toString();
        return isUsable(candidate) ? candidate : stripped;
    }
}
