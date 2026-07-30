package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 将 AI / PathRun entry 引用规范化为 scan {@link ApiDtos.EntryDto#id()}。
 *
 * <p>接受形式：
 * <ul>
 *   <li>{@code entry:<scanEntryId>} — 首选（如 {@code entry:entry-ann-1}）</li>
 *   <li>裸 {@code <scanEntryId>} — 当唯一匹配 scan entry id 时</li>
 *   <li>{@code entry:METHOD:route} — 当 method+route 唯一匹配一个 HTTP entry 时</li>
 * </ul>
 *
 * <p>稳定 code：{@code ENTRYPOINT_REF_MUST_BE_ENTRY}、{@code ENTRYPOINT_NOT_FOUND}、
 * {@code ENTRYPOINT_REF_AMBIGUOUS}。
 */
public final class EntryRefResolver {
    public static final String CODE_MUST_BE_ENTRY = "ENTRYPOINT_REF_MUST_BE_ENTRY";
    public static final String CODE_NOT_FOUND = "ENTRYPOINT_NOT_FOUND";
    public static final String CODE_AMBIGUOUS = "ENTRYPOINT_REF_AMBIGUOUS";

    private static final Set<String> HTTP_METHODS = Set.of(
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE");

    private EntryRefResolver() { }

    public enum Status {
        RESOLVED,
        MUST_BE_ENTRY,
        NOT_FOUND,
        AMBIGUOUS
    }

    public record Resolution(Status status, ApiDtos.EntryDto entry, String canonicalRef, String code) {
        public Resolution {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(code, "code");
            if (status == Status.RESOLVED) {
                Objects.requireNonNull(entry, "entry");
                Objects.requireNonNull(canonicalRef, "canonicalRef");
            } else if (entry != null || canonicalRef != null) {
                throw new IllegalArgumentException("unresolved resolution cannot carry entry");
            }
        }

        public boolean resolved() {
            return status == Status.RESOLVED;
        }
    }

    public static String canonicalRef(ApiDtos.EntryDto entry) {
        Objects.requireNonNull(entry, "entry");
        return "entry:" + entry.id();
    }

    /**
     * HTTP PathRun wire 形式，TraceProjectionService 使用：
     * {@code entry:METHOD:/route}。
     */
    public static String methodRouteRef(ApiDtos.EntryDto entry) {
        Objects.requireNonNull(entry, "entry");
        String method = entry.method() == null || entry.method().isBlank()
                ? "GET" : entry.method().trim().toUpperCase(Locale.ROOT);
        return "entry:" + method + ":" + normalizeRoute(entry.route());
    }

    /**
     * 原始 entry ref 的全部等价 join key（规范 id、METHOD:route、裸 id）。
     * StaticDynamicContraster 使用，使 {@code entry:entry-ann-*} 可 join 以
     * {@code entry:POST:/foo} 为 key 的 PathRun。
     */
    public static List<String> joinKeys(List<ApiDtos.EntryDto> entries, String rawRef) {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        String normalized = normalizeJoinRef(rawRef);
        if (!normalized.isBlank()) {
            keys.add(normalized);
        }
        Resolution resolution = resolve(entries, rawRef);
        if (resolution.resolved()) {
            keys.add(resolution.canonicalRef());
            keys.add(normalizeJoinRef(resolution.entry().id()));
            if ("HTTP".equalsIgnoreCase(resolution.entry().protocol())) {
                keys.add(methodRouteRef(resolution.entry()));
            }
        }
        // catalog resolve 失败时也接受 METHOD:route（孤儿 PathRun）。
        String methodRoute = extractMethodRouteKey(rawRef);
        if (!methodRoute.isBlank()) {
            keys.add(methodRoute);
        }
        return List.copyOf(keys);
    }

    /** Prefix-normalize without catalog resolve ({@code entry-ann-1} → {@code entry:entry-ann-1}). */
    public static String normalizeJoinRef(String ref) {
        if (ref == null || ref.isBlank()) return "";
        String trimmed = ref.trim();
        if (trimmed.startsWith("entry:")) return trimmed;
        if (trimmed.startsWith("entry-")) return "entry:" + trimmed;
        return "entry:" + trimmed;
    }

    public static boolean refsEquivalent(List<ApiDtos.EntryDto> entries, String left, String right) {
        if (left == null || right == null) return false;
        if (normalizeJoinRef(left).equals(normalizeJoinRef(right))) return true;
        List<String> leftKeys = joinKeys(entries, left);
        List<String> rightKeys = joinKeys(entries, right);
        for (String key : leftKeys) {
            if (rightKeys.contains(key)) return true;
        }
        return false;
    }

    public static Resolution resolve(List<ApiDtos.EntryDto> entries, String rawRef) {
        List<ApiDtos.EntryDto> catalog = List.copyOf(entries == null ? List.of() : entries);
        if (rawRef == null || rawRef.isBlank()) {
            return unresolved(Status.MUST_BE_ENTRY, CODE_MUST_BE_ENTRY);
        }
        String trimmed = rawRef.trim();
        if (trimmed.indexOf('\0') >= 0 || trimmed.indexOf('\r') >= 0 || trimmed.indexOf('\n') >= 0) {
            return unresolved(Status.MUST_BE_ENTRY, CODE_MUST_BE_ENTRY);
        }

        if (!trimmed.startsWith("entry:")) {
            ApiDtos.EntryDto byBareId = findById(catalog, trimmed);
            if (byBareId != null) {
                return resolved(byBareId);
            }
            // 裸 route / 臆造 path 不是 entry ref。
            return unresolved(Status.MUST_BE_ENTRY, CODE_MUST_BE_ENTRY);
        }

        String rest = trimmed.substring("entry:".length());
        if (rest.isBlank()) {
            return unresolved(Status.MUST_BE_ENTRY, CODE_MUST_BE_ENTRY);
        }

        ApiDtos.EntryDto byId = findById(catalog, rest);
        if (byId != null) {
            return resolved(byId);
        }

        int colon = rest.indexOf(':');
        if (colon > 0) {
            String method = rest.substring(0, colon).trim();
            String route = rest.substring(colon + 1).trim();
            if (isHttpMethod(method) && !route.isBlank()) {
                List<ApiDtos.EntryDto> matches = findByMethodRoute(catalog, method, route);
                if (matches.size() == 1) {
                    return resolved(matches.get(0));
                }
                if (matches.size() > 1) {
                    return unresolved(Status.AMBIGUOUS, CODE_AMBIGUOUS);
                }
                return unresolved(Status.NOT_FOUND, CODE_NOT_FOUND);
            }
        }

        return unresolved(Status.NOT_FOUND, CODE_NOT_FOUND);
    }

    public static ApiDtos.EntryDto require(List<ApiDtos.EntryDto> entries, String rawRef) {
        Resolution resolution = resolve(entries, rawRef);
        if (resolution.resolved()) {
            return resolution.entry();
        }
        if (resolution.status() == Status.NOT_FOUND) {
            throw new IllegalArgumentException(CODE_NOT_FOUND);
        }
        if (resolution.status() == Status.AMBIGUOUS) {
            throw new IllegalArgumentException(CODE_AMBIGUOUS);
        }
        throw new IllegalArgumentException(CODE_MUST_BE_ENTRY);
    }

    private static Resolution resolved(ApiDtos.EntryDto entry) {
        return new Resolution(Status.RESOLVED, entry, canonicalRef(entry), "OK");
    }

    private static Resolution unresolved(Status status, String code) {
        return new Resolution(status, null, null, code);
    }

    private static ApiDtos.EntryDto findById(List<ApiDtos.EntryDto> entries, String id) {
        for (ApiDtos.EntryDto entry : entries) {
            if (entry.id().equals(id)) return entry;
        }
        return null;
    }

    private static List<ApiDtos.EntryDto> findByMethodRoute(List<ApiDtos.EntryDto> entries,
                                                            String method, String route) {
        String normalizedMethod = method.toUpperCase(Locale.ROOT);
        String normalizedRoute = normalizeRoute(route);
        List<ApiDtos.EntryDto> matches = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entries) {
            if (!"HTTP".equalsIgnoreCase(entry.protocol())) continue;
            if (!normalizedMethod.equalsIgnoreCase(entry.method())) continue;
            if (normalizeRoute(entry.route()).equals(normalizedRoute)) {
                matches.add(entry);
            }
        }
        return matches;
    }

    private static boolean isHttpMethod(String value) {
        return value != null && HTTP_METHODS.contains(value.toUpperCase(Locale.ROOT));
    }

    private static String extractMethodRouteKey(String rawRef) {
        if (rawRef == null || rawRef.isBlank()) return "";
        String trimmed = rawRef.trim();
        String rest = trimmed.startsWith("entry:") ? trimmed.substring("entry:".length()) : trimmed;
        int colon = rest.indexOf(':');
        if (colon <= 0) return "";
        String method = rest.substring(0, colon).trim();
        String route = rest.substring(colon + 1).trim();
        if (!isHttpMethod(method) || route.isBlank()) return "";
        return "entry:" + method.toUpperCase(Locale.ROOT) + ":" + normalizeRoute(route);
    }

    private static String normalizeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String value = route.trim();
        if (!value.startsWith("/")) value = "/" + value;
        if (value.length() > 1 && value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
}
