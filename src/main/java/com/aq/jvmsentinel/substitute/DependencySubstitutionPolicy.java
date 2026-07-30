package com.aq.jvmsentinel.substitute;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 不可变、版本化的 substitution 数据。刻意不包含 sandbox、
 * 说明：network-forwarding/host-path/database-connection 或 process-execution 权限。
 */
public record DependencySubstitutionPolicy(
        int schemaVersion,
        Scope scope,
        Budget budget,
        List<HttpRoute> httpRoutes,
        List<JdbcRule> jdbcRules,
        List<FileGrant> fileGrants,
        List<ProcessSimulation> processSimulations) implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    public static final int SCHEMA_VERSION = 1;
    private static final int MAX_RULES = 128;

    public DependencySubstitutionPolicy {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        scope = Objects.requireNonNull(scope, "scope");
        budget = Objects.requireNonNull(budget, "budget");
        httpRoutes = boundedCopy(httpRoutes, "httpRoutes");
        jdbcRules = boundedCopy(jdbcRules, "jdbcRules");
        fileGrants = boundedCopy(fileGrants, "fileGrants");
        processSimulations = boundedCopy(processSimulations, "processSimulations");
        unique(httpRoutes.stream().map(r -> r.method() + " " + r.path()).toList(), "HTTP route");
        unique(jdbcRules.stream().map(JdbcRule::normalizedSql).toList(), "JDBC rule");
        unique(fileGrants.stream().map(FileGrant::relativePath).toList(), "file grant");
        unique(processSimulations.stream().map(ProcessSimulation::key).toList(), "process simulation");
    }

    public String digest() {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(schemaVersion);
            put(out, scope.projectId());
            put(out, scope.artifactDigest());
            put(out, scope.scanId());
            put(out, scope.taskId());
            out.writeLong(budget.maxOperations());
            out.writeLong(budget.maxTranscriptBytes());
            out.writeLong(budget.maxBodyBytes());
            writeList(out, httpRoutes.stream().map(HttpRoute::canonical).toList());
            writeList(out, jdbcRules.stream().map(JdbcRule::canonical).toList());
            writeList(out, fileGrants.stream().map(FileGrant::canonical).toList());
            writeList(out, processSimulations.stream().map(ProcessSimulation::canonical).toList());
            out.flush();
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
        } catch (IOException | NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    @Override
    public String toString() {
        return "DependencySubstitutionPolicy[schemaVersion=" + schemaVersion + ",scope=" + scope
                + ",digest=" + digest() + ",httpRoutes=" + httpRoutes.size() + ",jdbcRules="
                + jdbcRules.size() + ",fileGrants=" + fileGrants.size() + ",processSimulations="
                + processSimulations.size() + "]";
    }

    private static <T> List<T> boundedCopy(List<T> values, String name) {
        Objects.requireNonNull(values, name);
        if (values.size() > MAX_RULES) throw new IllegalArgumentException(name + " exceeds limit");
        if (values.stream().anyMatch(Objects::isNull)) throw new IllegalArgumentException(name + " contains null");
        return List.copyOf(values);
    }

    private static void unique(List<String> keys, String name) {
        if (new LinkedHashSet<>(keys).size() != keys.size()) {
            throw new IllegalArgumentException("duplicate " + name);
        }
    }

    private static void writeList(DataOutputStream out, List<String> values) throws IOException {
        out.writeInt(values.size());
        for (String value : values) put(out, value);
    }

    private static void put(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    public record Scope(String projectId, String artifactDigest, String scanId, String taskId)
            implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
        private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
        private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");

        public Scope {
            projectId = id(projectId, "projectId");
            if (!DIGEST.matcher(Objects.requireNonNull(artifactDigest, "artifactDigest")).matches()) {
                throw new IllegalArgumentException("artifactDigest must be a lowercase SHA-256");
            }
            scanId = id(scanId, "scanId");
            taskId = id(taskId, "taskId");
        }

        private static String id(String value, String name) {
            if (!ID.matcher(Objects.requireNonNull(value, name)).matches()) {
                throw new IllegalArgumentException(name + " contains invalid characters");
            }
            return value;
        }
    }

    public record Budget(long maxOperations, long maxTranscriptBytes, long maxBodyBytes)
            implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public Budget {
            if (maxOperations <= 0 || maxOperations > 100_000) {
                throw new IllegalArgumentException("maxOperations is outside the hard limit");
            }
            if (maxTranscriptBytes <= 0 || maxTranscriptBytes > 64L * 1024 * 1024) {
                throw new IllegalArgumentException("maxTranscriptBytes is outside the hard limit");
            }
            if (maxBodyBytes <= 0 || maxBodyBytes > 1024L * 1024) {
                throw new IllegalArgumentException("maxBodyBytes is outside the hard limit");
            }
        }
    }

    public enum Provenance {
        USER_SNAPSHOT,
        RECORDED_REPLAY,
        RULE_GENERATED,
        AI_INFERRED
    }

    public record HttpRoute(String method, String path, int status, String contentType,
                            String responseBody, Provenance provenance) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public HttpRoute {
            method = token(method, "method", 16).toUpperCase(java.util.Locale.ROOT);
            path = routePath(path);
            if (status < 100 || status > 599) throw new IllegalArgumentException("invalid HTTP status");
            contentType = headerText(contentType, "contentType", 128);
            responseBody = text(responseBody, "responseBody", 1024 * 1024, true);
            provenance = Objects.requireNonNull(provenance, "provenance");
        }

        private String canonical() {
            return String.join("\u0000", method, path, Integer.toString(status), contentType,
                    responseBody, provenance.name());
        }

        @Override
        public String toString() {
            return "HttpRoute[method=" + method + ",path=" + path + ",status=" + status
                    + ",contentType=" + contentType + ",responseBody=<redacted:"
                    + responseBody.length() + " chars>,provenance=" + provenance + "]";
        }
    }

    /** 精确 normalized-SQL 规则；无 dialect 仿真，无 database connection string。 */
    public record JdbcRule(String normalizedSql, List<String> columns, List<List<String>> rows,
                           Provenance provenance) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public JdbcRule {
            normalizedSql = normalizeSql(normalizedSql);
            columns = stringList(columns, "columns", 128, 128);
            Objects.requireNonNull(rows, "rows");
            if (rows.size() > 1024) throw new IllegalArgumentException("rows exceeds limit");
            List<List<String>> copied = new ArrayList<>(rows.size());
            for (List<String> row : rows) {
                List<String> values = stringList(row, "row", 128, 4096);
                if (values.size() != columns.size()) throw new IllegalArgumentException("row width mismatch");
                copied.add(values);
            }
            rows = List.copyOf(copied);
            provenance = Objects.requireNonNull(provenance, "provenance");
        }

        private String canonical() {
            StringBuilder value = new StringBuilder(normalizedSql).append('\u0000');
            columns.forEach(column -> value.append(column).append('\u0001'));
            value.append('\u0000');
            rows.forEach(row -> {
                row.forEach(cell -> value.append(cell).append('\u0001'));
                value.append('\u0002');
            });
            return value.append(provenance.name()).toString();
        }

        @Override
        public String toString() {
            return "JdbcRule[normalizedSqlSha256=" + sha256Text(normalizedSql) + ",columns="
                    + columns.size() + ",rows=" + rows.size() + ",provenance=" + provenance + "]";
        }
    }

    /** 仅相对 POSIX 风格 tmpfs path。 */
    public record FileGrant(String relativePath, boolean readable, boolean writable,
                            String seedContent, Provenance provenance) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public FileGrant {
            relativePath = normalizeRelativePath(relativePath);
            if (!readable && !writable) throw new IllegalArgumentException("file grant has no access");
            seedContent = text(seedContent, "seedContent", 1024 * 1024, true);
            provenance = Objects.requireNonNull(provenance, "provenance");
        }

        private String canonical() {
            return String.join("\u0000", relativePath, Boolean.toString(readable),
                    Boolean.toString(writable), seedContent, provenance.name());
        }

        @Override
        public String toString() {
            return "FileGrant[relativePath=" + relativePath + ",readable=" + readable
                    + ",writable=" + writable + ",seedContent=<redacted:" + seedContent.length()
                    + " chars>,provenance=" + provenance + "]";
        }
    }

    /** 精确 argv 匹配无害模拟结果；永不授予 execution。 */
    public record ProcessSimulation(List<String> argv, int exitCode, String stdout, String stderr,
                                    Provenance provenance) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public ProcessSimulation {
            argv = stringList(argv, "argv", 32, 4096);
            if (argv.isEmpty()) throw new IllegalArgumentException("argv is empty");
            stdout = text(stdout, "stdout", 64 * 1024, true);
            stderr = text(stderr, "stderr", 64 * 1024, true);
            provenance = Objects.requireNonNull(provenance, "provenance");
        }

        String key() {
            return String.join("\u0000", argv);
        }

        private String canonical() {
            return key() + "\u0001" + exitCode + "\u0001" + stdout + "\u0001" + stderr
                    + "\u0001" + provenance.name();
        }

        @Override
        public String toString() {
            return "ProcessSimulation[argvSha256=" + sha256Text(key()) + ",exitCode=" + exitCode
                    + ",stdout=<redacted:" + stdout.length() + " chars>,stderr=<redacted:"
                    + stderr.length() + " chars>,provenance=" + provenance + "]";
        }
    }

    static String normalizeSql(String value) {
        value = text(value, "normalizedSql", 16 * 1024, false);
        StringBuilder normalized = new StringBuilder(value.length());
        char quote = 0;
        boolean pendingSpace = false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (quote != 0) {
                normalized.append(current);
                if (current == quote) {
                    if (index + 1 < value.length() && value.charAt(index + 1) == quote) {
                        normalized.append(value.charAt(++index));
                    } else {
                        quote = 0;
                    }
                }
                continue;
            }
            if (current == '\'' || current == '"' || current == '`') {
                if (pendingSpace && !normalized.isEmpty()) normalized.append(' ');
                pendingSpace = false;
                quote = current;
                normalized.append(current);
            } else if (Character.isWhitespace(current)) {
                pendingSpace = !normalized.isEmpty();
            } else {
                if (pendingSpace) normalized.append(' ');
                pendingSpace = false;
                normalized.append(Character.toLowerCase(current));
            }
        }
        if (quote != 0) throw new IllegalArgumentException("normalizedSql contains an unterminated quote");
        return normalized.toString().trim();
    }

    private static String routePath(String value) {
        value = text(value, "path", 2048, false);
        if (!value.startsWith("/") || value.startsWith("//") || value.contains("?")
                || value.contains("#") || value.contains("\\") || value.contains("..")) {
            throw new IllegalArgumentException("HTTP route must be a fixed absolute path");
        }
        return value;
    }

    private static String normalizeRelativePath(String value) {
        value = text(value, "relativePath", 1024, false);
        if (value.startsWith("/") || value.startsWith("\\") || value.contains("\\")
                || value.contains(":") || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new IllegalArgumentException("file grant must be a relative POSIX path");
        }
        String[] parts = value.split("/");
        if (parts.length == 0) throw new IllegalArgumentException("empty file path");
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException("file path traversal is forbidden");
            }
        }
        return value;
    }

    private static List<String> stringList(List<String> values, String name, int maxSize, int maxText) {
        Objects.requireNonNull(values, name);
        if (values.size() > maxSize) throw new IllegalArgumentException(name + " exceeds limit");
        return values.stream().map(value -> text(value, name + " item", maxText, true)).toList();
    }

    private static String token(String value, String name, int maxLength) {
        value = text(value, name, maxLength, false);
        if (!value.matches("[A-Za-z]+")) throw new IllegalArgumentException("invalid " + name);
        return value;
    }

    private static String headerText(String value, String name, int maxLength) {
        value = text(value, name, maxLength, false);
        if (value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    private static String sha256Text(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String text(String value, String name, int maxLength, boolean allowEmpty) {
        Objects.requireNonNull(value, name);
        if ((!allowEmpty && value.isBlank()) || value.length() > maxLength
                || value.chars().anyMatch(c -> c == 0)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}
