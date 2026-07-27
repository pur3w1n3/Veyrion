package com.aq.jvmsentinel.analysis;

import java.util.Locale;

/** Static sink.category → CWE mapping for triage / report hints. */
public final class CweMapper {
    private CweMapper() {
    }

    public static String cweMappingFor(String category) {
        if (category == null || category.isBlank()) return null;
        return switch (category.trim().toUpperCase(Locale.ROOT)) {
            case "SQL", "SQL_INJECTION" -> "CWE-89";
            case "JNDI", "LDAP" -> "CWE-90";
            case "COMMAND", "RCE", "OS_COMMAND" -> "CWE-78";
            case "PATH_TRAVERSAL", "PATH", "FILE" -> "CWE-22";
            case "DESERIALIZATION" -> "CWE-502";
            case "SSRF" -> "CWE-918";
            case "XSS" -> "CWE-79";
            case "XXE" -> "CWE-611";
            default -> null;
        };
    }
}
