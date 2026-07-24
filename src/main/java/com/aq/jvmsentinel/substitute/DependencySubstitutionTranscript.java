package com.aq.jvmsentinel.substitute;

import com.aq.jvmsentinel.control.JsonCodec;

import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Strictly bounded, append-only dependency substitution evidence. */
public final class DependencySubstitutionTranscript implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    public static final int SCHEMA_VERSION = 1;

    public enum Kind { HTTP, JDBC, FILE, PROCESS }
    public enum StopReason { CONTINUE, COMPLETED, POLICY_REJECTED, BUDGET_EXHAUSTED, IO_FAILURE }

    public record BudgetSnapshot(long operationsUsed, long maxOperations,
                                 long transcriptBytesUsed, long maxTranscriptBytes)
            implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
    }

    /**
     * {@code executed} means the local substitute operation ran.  It never means
     * that an external HTTP service, database, host file, or host process ran.
     */
    public record Result(
            int schemaVersion,
            DependencySubstitutionPolicy.Scope scope,
            String policyDigest,
            long sequence,
            Kind kind,
            String operation,
            String requestSummary,
            String responseSummary,
            DependencySubstitutionPolicy.Provenance provenance,
            boolean executed,
            String digest,
            BudgetSnapshot budget,
            StopReason stopReason) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        public Result {
            if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
            scope = Objects.requireNonNull(scope, "scope");
            requireDigest(policyDigest, "policyDigest");
            if (sequence < 0) throw new IllegalArgumentException("negative sequence");
            kind = Objects.requireNonNull(kind, "kind");
            operation = bounded(operation, "operation", 128);
            requestSummary = bounded(requestSummary, "requestSummary", 4096);
            responseSummary = bounded(responseSummary, "responseSummary", 4096);
            provenance = Objects.requireNonNull(provenance, "provenance");
            requireDigest(digest, "digest");
            budget = Objects.requireNonNull(budget, "budget");
            stopReason = Objects.requireNonNull(stopReason, "stopReason");
        }

        public Map<String, Object> toMap() {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("schemaVersion", schemaVersion);
            value.put("scope", Map.of(
                    "projectId", scope.projectId(),
                    "artifactDigest", scope.artifactDigest(),
                    "scanId", scope.scanId(),
                    "taskId", scope.taskId()));
            value.put("policyDigest", policyDigest);
            value.put("sequence", sequence);
            value.put("kind", kind.name());
            value.put("operation", operation);
            value.put("requestSummary", requestSummary);
            value.put("responseSummary", responseSummary);
            value.put("provenance", provenance.name());
            value.put("executed", executed);
            value.put("digest", digest);
            value.put("budget", Map.of(
                    "operationsUsed", budget.operationsUsed(),
                    "maxOperations", budget.maxOperations(),
                    "transcriptBytesUsed", budget.transcriptBytesUsed(),
                    "maxTranscriptBytes", budget.maxTranscriptBytes()));
            value.put("stopReason", stopReason.name());
            return value;
        }
    }

    private final DependencySubstitutionPolicy.Scope scope;
    private final String policyDigest;
    private final DependencySubstitutionPolicy.Budget budget;
    private final List<Result> results = new ArrayList<>();
    private long encodedBytes;
    private StopReason finalStopReason = StopReason.CONTINUE;

    public DependencySubstitutionTranscript(DependencySubstitutionPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        scope = policy.scope();
        policyDigest = policy.digest();
        budget = policy.budget();
        encodedBytes = toJson().getBytes(StandardCharsets.UTF_8).length;
        if (encodedBytes > budget.maxTranscriptBytes()) {
            finalStopReason = StopReason.BUDGET_EXHAUSTED;
            throw new BudgetExceededException("transcript envelope exceeds byte budget");
        }
    }

    public synchronized Result append(Kind kind, String operation, String requestSummary,
                                      String responseSummary,
                                      DependencySubstitutionPolicy.Provenance provenance,
                                      boolean executed, StopReason stopReason) {
        if (finalStopReason != StopReason.CONTINUE) {
            throw new IllegalStateException("transcript is stopped: " + finalStopReason);
        }
        if (results.size() >= budget.maxOperations()) {
            finalStopReason = StopReason.BUDGET_EXHAUSTED;
            throw new BudgetExceededException("operation budget exhausted");
        }

        long sequence = results.size();
        String request = Redactor.redact(requestSummary);
        String response = Redactor.redact(responseSummary);
        String digest = eventDigest(sequence, kind, operation, request, response, provenance, executed, stopReason);
        long eventBytes = 0;
        for (int attempt = 0; attempt < 8; attempt++) {
            long projectedBytes = encodedBytes + eventBytes;
            Result provisional = new Result(SCHEMA_VERSION, scope, policyDigest, sequence, kind, operation,
                    request, response, provenance, executed, digest,
                    new BudgetSnapshot(sequence + 1, budget.maxOperations(), projectedBytes,
                            budget.maxTranscriptBytes()), stopReason);
            // Charge a fixed envelope/comma/digit-growth allowance so the complete
            // serialized transcript remains strictly below the configured budget.
            long measured = JsonCodec.stringify(provisional.toMap()).getBytes(StandardCharsets.UTF_8).length + 32;
            if (measured == eventBytes) break;
            eventBytes = measured;
        }
        if (encodedBytes + eventBytes > budget.maxTranscriptBytes()) {
            finalStopReason = StopReason.BUDGET_EXHAUSTED;
            throw new BudgetExceededException("transcript byte budget exhausted");
        }
        encodedBytes += eventBytes;
        Result result = new Result(SCHEMA_VERSION, scope, policyDigest, sequence, kind, operation,
                request, response, provenance, executed, digest,
                new BudgetSnapshot(sequence + 1, budget.maxOperations(), encodedBytes, budget.maxTranscriptBytes()),
                stopReason);
        results.add(result);
        if (stopReason != StopReason.CONTINUE) finalStopReason = stopReason;
        return result;
    }

    public synchronized void complete() {
        if (finalStopReason != StopReason.CONTINUE) {
            throw new IllegalStateException("transcript is stopped: " + finalStopReason);
        }
        finalStopReason = StopReason.COMPLETED;
    }

    public synchronized List<Result> results() {
        return List.copyOf(results);
    }

    public synchronized StopReason stopReason() {
        return finalStopReason;
    }

    public synchronized String toJson() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", SCHEMA_VERSION);
        value.put("scope", Map.of(
                "projectId", scope.projectId(),
                "artifactDigest", scope.artifactDigest(),
                "scanId", scope.scanId(),
                "taskId", scope.taskId()));
        value.put("policyDigest", policyDigest);
        value.put("results", results.stream().map(Result::toMap).toList());
        value.put("budget", Map.of(
                "operationsUsed", results.size(),
                "maxOperations", budget.maxOperations(),
                "transcriptBytesUsed", encodedBytes,
                "maxTranscriptBytes", budget.maxTranscriptBytes()));
        value.put("stopReason", finalStopReason.name());
        String json = JsonCodec.stringify(value);
        if (json.getBytes(StandardCharsets.UTF_8).length > budget.maxTranscriptBytes()) {
            throw new BudgetExceededException("serialized transcript exceeds byte budget");
        }
        return json;
    }

    /** Digest of the complete bounded transcript, including its terminal stop reason. */
    public synchronized String digest() {
        return sha256(toJson());
    }

    private String eventDigest(long sequence, Kind kind, String operation, String request, String response,
                               DependencySubstitutionPolicy.Provenance provenance, boolean executed,
                               StopReason stopReason) {
        String previous = results.isEmpty() ? policyDigest : results.get(results.size() - 1).digest();
        return sha256(String.join("\u0000", policyDigest, previous, Long.toString(sequence), kind.name(),
                operation, request, response, provenance.name(), Boolean.toString(executed), stopReason.name()));
    }

    static String summarize(String label, byte[] value) {
        return label + "[bytes=" + value.length + ",sha256=" + sha256(value) + "]";
    }

    static String sha256(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void requireDigest(String value, String name) {
        if (!Pattern.matches("[0-9a-f]{64}", Objects.requireNonNull(value, name))) {
            throw new IllegalArgumentException(name + " must be a lowercase SHA-256");
        }
    }

    private static String bounded(String value, String name, int maxLength) {
        Objects.requireNonNull(value, name);
        if (value.length() > maxLength || value.chars().anyMatch(c -> c == 0)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    public static final class BudgetExceededException extends IllegalStateException {
        public BudgetExceededException(String message) {
            super(message);
        }
    }

    /** Redacts common secret forms without attempting to retain the sensitive value. */
    static final class Redactor {
        private static final Pattern KEY_VALUE = Pattern.compile(
                "(?i)(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key)\\s*[:=]\\s*([^,;\\s]+)");
        private static final Pattern BEARER = Pattern.compile("(?i)bearer\\s+[A-Za-z0-9._~+/=-]+");

        private Redactor() { }

        static String redact(String value) {
            Objects.requireNonNull(value, "summary");
            String redacted = BEARER.matcher(value).replaceAll("Bearer_<redacted>");
            redacted = KEY_VALUE.matcher(redacted).replaceAll("$1=<redacted>");
            return bounded(redacted.replaceAll("[\\r\\n\\t]", " "), "summary", 4096);
        }
    }
}
