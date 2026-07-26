package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Canonicalizes AI / PathRun entry references onto scan {@link ApiDtos.EntryDto#id()}.
 *
 * <p>Accepted forms:
 * <ul>
 *   <li>{@code entry:&lt;scanEntryId&gt;} — preferred (e.g. {@code entry:entry-ann-1})</li>
 *   <li>bare {@code &lt;scanEntryId&gt;} when it uniquely matches a scan entry id</li>
 *   <li>{@code entry:METHOD:route} when that method+route uniquely matches one HTTP entry</li>
 * </ul>
 *
 * <p>Stable codes: {@code ENTRYPOINT_REF_MUST_BE_ENTRY}, {@code ENTRYPOINT_NOT_FOUND},
 * {@code ENTRYPOINT_REF_AMBIGUOUS}.
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
            // Raw routes / invented paths are not entry refs.
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
