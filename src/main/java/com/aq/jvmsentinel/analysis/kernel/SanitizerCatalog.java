package com.aq.jvmsentinel.analysis.kernel;

import java.util.Locale;
import java.util.Optional;

/**
 * Minimal known sanitizer / validator markers for kernel summaries and taint hooks.
 * Matching is declarative only; it does not prove runtime neutralization.
 */
public final class SanitizerCatalog {
    private SanitizerCatalog() {
    }

    public static Optional<String> match(String owner, String name) {
        String o = normalizeOwner(owner);
        String n = name == null ? "" : name;
        String lowerName = n.toLowerCase(Locale.ROOT);
        if (o.equals("org.springframework.web.util.HtmlUtils")
                && (n.equals("htmlEscape") || n.equals("htmlEscapeDecimal") || n.equals("htmlEscapeHex"))) {
            return Optional.of("html-escape");
        }
        if (o.equals("org.apache.commons.text.StringEscapeUtils")
                || o.equals("org.apache.commons.lang.StringEscapeUtils")
                || o.equals("org.apache.commons.lang3.StringEscapeUtils")) {
            if (n.startsWith("escape") || n.startsWith("unescape")) {
                return Optional.of("commons-escape");
            }
        }
        if (o.equals("java.net.URLEncoder") && n.equals("encode")) {
            return Optional.of("url-encode");
        }
        if (o.equals("org.owasp.encoder.Encode") && n.startsWith("for")) {
            return Optional.of("owasp-encode");
        }
        if ((o.contains("PreparedStatement") || o.endsWith(".PreparedStatement"))
                && (n.equals("setString") || n.equals("setObject") || n.equals("setInt")
                || n.equals("setLong") || n.equals("setBoolean"))) {
            return Optional.of("jdbc-parameterized");
        }
        if (o.equals("java.util.regex.Pattern") && (n.equals("matcher") || n.equals("matches"))) {
            return Optional.of("regex-validate");
        }
        if (lowerName.contains("sanitize")
                || lowerName.contains("escapehtml")
                || lowerName.contains("htmlencode")
                || lowerName.contains("htmlescape")
                || lowerName.startsWith("escape") && (lowerName.contains("sql") || lowerName.contains("html")
                || lowerName.contains("xml") || lowerName.contains("js"))) {
            return Optional.of("name-heuristic-sanitize");
        }
        if (lowerName.contains("whitelist") || lowerName.contains("allowlist")
                || lowerName.equals("validate") || lowerName.startsWith("validate")) {
            return Optional.of("name-heuristic-validate");
        }
        return Optional.empty();
    }

    public static Optional<String> matchGuard(String owner, String name) {
        String o = normalizeOwner(owner);
        String n = name == null ? "" : name;
        String hay = (o + "#" + n).toLowerCase(Locale.ROOT);
        if (hay.contains("preauthorize")
                || hay.contains("hasrole")
                || hay.contains("hasauthority")
                || hay.contains("checkpermission")
                || hay.contains("requirespermissions")
                || hay.contains("rolesallowed")
                || hay.contains("secured")
                || n.equals("doFilter") && o.toLowerCase(Locale.ROOT).contains("filter")
                || n.equalsIgnoreCase("authenticate")
                || n.equalsIgnoreCase("authorize")
                || n.toLowerCase(Locale.ROOT).startsWith("checkauth")
                || n.toLowerCase(Locale.ROOT).contains("requirelogin")) {
            return Optional.of("guard-call");
        }
        return Optional.empty();
    }

    private static String normalizeOwner(String owner) {
        return owner == null ? "" : owner.replace('/', '.');
    }
}
