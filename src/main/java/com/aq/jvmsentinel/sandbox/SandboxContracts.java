package com.aq.jvmsentinel.sandbox;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

final class SandboxContracts {
    static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private SandboxContracts() { }

    static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!ID.matcher(value).matches() || value.equals(".") || value.equals("..")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
        return value;
    }

    static String text(String value, String name, int maxLength) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > maxLength || value.chars().anyMatch(c -> c < 0x20)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    static List<String> command(List<String> values, String name) {
        Objects.requireNonNull(values, name);
        if (values.isEmpty() || values.size() > 128) throw new IllegalArgumentException("invalid " + name);
        return values.stream().map(value -> text(value, name + " item", 4096)).toList();
    }

    static URI httpBase(URI value, String name) {
        Objects.requireNonNull(value, name);
        if (!("http".equalsIgnoreCase(value.getScheme()) || "https".equalsIgnoreCase(value.getScheme()))
                || value.getHost() == null || value.getRawQuery() != null || value.getRawFragment() != null
                || value.getRawUserInfo() != null) {
            throw new IllegalArgumentException(name + " must be an HTTP(S) base URI without credentials, query, or fragment");
        }
        String path = value.getPath();
        if (path == null || path.isEmpty()) path = "/";
        if (!path.endsWith("/")) path += "/";
        return URI.create(value.getScheme() + "://" + value.getRawAuthority() + path);
    }

    static URI resolve(URI base, String relative) {
        return base.resolve(relative);
    }
}
