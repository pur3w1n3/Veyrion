package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.policy.NetworkMode;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Bounded, same-origin client for the authenticated Worker control-plane contract. */
public final class WorkerControlPlaneClient {
    private static final int CONTRACT_VERSION = 1;
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 1_500_000;
    private static final Set<String> SNAPSHOT_FIELDS = Set.of(
            "schemaVersion", "workerContractVersion", "projectId", "artifactDigest", "scanId", "taskId",
            "lifecycle", "status", "updatedAt", "targetEntryId", "authorized", "fixtureOnly",
            "requiredCapability", "dynamicExecutionMode", "resourceBudget", "networkPolicy", "lease", "checkpoint",
            "stopReason", "failureCode");
    private static final Set<String> LEASE_FIELDS = Set.of(
            "schemaVersion", "workerContractVersion", "projectId", "artifactDigest", "scanId", "taskId",
            "leaseId", "workerId", "capability", "issuedAt", "heartbeatAt", "expiresAt");
    private static final Set<String> TRACE_FIELDS = Set.of(
            "schemaVersion", "workerContractVersion", "projectId", "artifactDigest", "scanId", "taskId",
            "sequence", "previousDigest", "digest", "emittedAt", "payloadBytes",
            "traceHeadDigest", "totalPayloadBytes");

    private final URI baseUri;
    private final String workerToken;
    private final Duration timeout;
    private final int maxResponseBytes;
    private final HttpClient http;

    public WorkerControlPlaneClient(URI baseUri, String workerToken, Duration timeout) {
        this(baseUri, workerToken, timeout, DEFAULT_MAX_RESPONSE_BYTES,
                HttpClient.newBuilder().connectTimeout(timeout)
                        .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    public WorkerControlPlaneClient(URI baseUri, String workerToken, Duration timeout,
                                    int maxResponseBytes, HttpClient http) {
        this.baseUri = safeBase(baseUri);
        this.workerToken = secret(workerToken);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("timeout must be positive and at most five minutes");
        }
        if (maxResponseBytes <= 0 || maxResponseBytes > DEFAULT_MAX_RESPONSE_BYTES) {
            throw new IllegalArgumentException("maxResponseBytes is outside contract limits");
        }
        this.maxResponseBytes = maxResponseBytes;
        this.http = Objects.requireNonNull(http, "http");
    }

    public List<TaskDescriptor> list(String projectId, String scanId) {
        WorkerContracts.id(projectId, "projectId");
        WorkerContracts.id(scanId, "scanId");
        String query = "projectId=" + encode(projectId) + "&scanId=" + encode(scanId);
        return list(resolve("tasks?" + query));
    }

    public List<TaskDescriptor> list() {
        return list(resolve("tasks"));
    }

    private List<TaskDescriptor> list(URI endpoint) {
        Map<String, Object> root = send("GET", endpoint, null, null);
        requireExactFields(root, Set.of(
                "schemaVersion", "workerContractVersion", "dynamicExecutionMode", "tasks"), "task list");
        requireVersions(root);
        Object value = root.get("tasks");
        if (!(value instanceof List<?> tasks) || tasks.size() > WorkerContracts.MAX_COLLECTION_SIZE) {
            throw protocol("tasks must be a bounded array", null);
        }
        List<TaskDescriptor> result = new ArrayList<>();
        for (Object task : tasks) result.add(parseTask(object(task, "task")));
        return List.copyOf(result);
    }

    public TaskDescriptor get(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        String query = "projectId=" + encode(scope.projectId())
                + "&artifactDigest=" + encode(scope.artifactDigest())
                + "&scanId=" + encode(scope.scanId());
        return parseTask(send("GET", resolve("tasks/" + scope.taskId() + "?" + query), null, null));
    }

    public WorkerLease lease(TaskScope scope, String workerId, Set<WorkerCapability> capabilities,
                             Duration duration) {
        WorkerContracts.id(workerId, "workerId");
        Objects.requireNonNull(capabilities, "capabilities");
        if (capabilities.isEmpty() || capabilities.size() > WorkerCapability.values().length) {
            throw new IllegalArgumentException("capabilities is invalid");
        }
        Objects.requireNonNull(duration, "duration");
        long seconds = duration.toSeconds();
        if (seconds <= 0 || seconds > 86_400 || !duration.equals(Duration.ofSeconds(seconds))) {
            throw new IllegalArgumentException("lease duration is invalid");
        }
        Map<String, Object> body = scopeBody(scope);
        body.put("workerId", workerId);
        body.put("capabilities", capabilities.stream().map(Enum::name).sorted().toList());
        body.put("durationSeconds", seconds);
        return parseLease(sendMutation(scope, "lease", body, idempotency(scope, "lease", workerId)));
    }

    public TaskDescriptor start(TaskScope scope, String leaseId, String workerId) {
        return parseTask(sendLeaseMutation(scope, "start", leaseId, workerId, Map.of()));
    }

    /**
     * Renews the worker lease and optionally publishes a sanitized step progress line for the GUI.
     * Each call uses a unique idempotency key so renewals are not replay-suppressed.
     */
    public WorkerLease heartbeat(TaskScope scope, String leaseId, String workerId, Duration extension,
                                 String progressDetail) {
        WorkerContracts.id(leaseId, "leaseId");
        WorkerContracts.id(workerId, "workerId");
        Objects.requireNonNull(extension, "extension");
        long seconds = extension.toSeconds();
        if (seconds <= 0 || seconds > 86_400 || !extension.equals(Duration.ofSeconds(seconds))) {
            throw new IllegalArgumentException("heartbeat extension is invalid");
        }
        Map<String, Object> body = scopeBody(scope);
        body.put("leaseId", leaseId);
        body.put("workerId", workerId);
        body.put("extensionSeconds", seconds);
        if (progressDetail != null && !progressDetail.isBlank()) {
            String value = progressDetail.replaceAll("[\\p{Cntrl}&&[^\\t]]", " ").strip();
            if (value.length() > 240) value = value.substring(0, 240);
            if (!value.isEmpty()) body.put("progressDetail", value);
        }
        String key = idempotency(scope, "heartbeat",
                leaseId + "-" + Long.toHexString(System.nanoTime()));
        return parseLease(sendMutation(scope, "heartbeat", body, key));
    }

    public TraceCommit commitTrace(TaskScope scope, String leaseId, String workerId, TraceChunk chunk) {
        Objects.requireNonNull(chunk, "chunk");
        if (!scope.equals(chunk.scope())) throw new SecurityException("trace scope mismatch");
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("sequence", chunk.sequence());
        extra.put("previousDigest", chunk.previousDigest());
        extra.put("emittedAt", chunk.emittedAt().toString());
        extra.put("payloadBase64", Base64.getEncoder().encodeToString(chunk.payload()));
        extra.put("digest", chunk.digest());
        Map<String, Object> response = sendLeaseMutation(scope, "trace", leaseId, workerId, extra);
        requireExactFields(response, TRACE_FIELDS, "trace response");
        requireVersions(response);
        requireScope(response, scope);
        long sequence = integer(response, "sequence");
        if (sequence != chunk.sequence()
                || !Objects.equals(optionalString(response, "previousDigest"), chunk.previousDigest())
                || !string(response, "digest").equals(chunk.digest())
                || integer(response, "payloadBytes") != chunk.payload().length) {
            throw protocol("trace acknowledgement does not match submitted chunk", null);
        }
        return new TraceCommit(sequence, string(response, "digest"),
                string(response, "traceHeadDigest"), integer(response, "totalPayloadBytes"));
    }

    public TaskDescriptor complete(TaskScope scope, String leaseId, String workerId) {
        return parseTask(sendLeaseMutation(scope, "complete", leaseId, workerId, Map.of()));
    }

    public TaskDescriptor fail(TaskScope scope, String leaseId, String workerId,
                               StopReason reason, String failureCode) {
        return fail(scope, leaseId, workerId, reason, failureCode, null);
    }

    public TaskDescriptor fail(TaskScope scope, String leaseId, String workerId,
                               StopReason reason, String failureCode, String failureDiagnostic) {
        Objects.requireNonNull(reason, "reason");
        WorkerContracts.id(failureCode, "failureCode");
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("reason", reason.name());
        fields.put("failureCode", failureCode);
        if (failureDiagnostic != null && !failureDiagnostic.isBlank()) {
            String value = failureDiagnostic.strip();
            if (value.length() > 2048 || value.chars().anyMatch(character ->
                    Character.isISOControl(character) && character != '\n' && character != '\t')) {
                throw new IllegalArgumentException("failureDiagnostic is invalid");
            }
            fields.put("failureDiagnostic", value);
        }
        return parseTask(sendLeaseMutation(scope, "fail", leaseId, workerId, fields));
    }

    private Map<String, Object> sendLeaseMutation(TaskScope scope, String action, String leaseId,
                                                   String workerId, Map<String, Object> extra) {
        WorkerContracts.id(leaseId, "leaseId");
        WorkerContracts.id(workerId, "workerId");
        Map<String, Object> body = scopeBody(scope);
        body.put("leaseId", leaseId);
        body.put("workerId", workerId);
        body.putAll(extra);
        String suffix = action.equals("trace") ? Long.toString((Long) extra.get("sequence")) : leaseId;
        return sendMutation(scope, action, body, idempotency(scope, action, suffix));
    }

    private Map<String, Object> sendMutation(TaskScope scope, String action,
                                              Map<String, Object> body, String idempotencyKey) {
        return send("POST", resolve("tasks/" + scope.taskId() + "/" + action), body, idempotencyKey);
    }

    private Map<String, Object> send(String method, URI uri, Map<String, Object> body, String idempotencyKey) {
        if (!sameOrigin(baseUri, uri)) throw new SecurityException("cross-origin Worker request rejected");
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("Accept", "application/json")
                .header("X-Sentinel-Worker-Authorization", workerToken);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        if (body == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(
                    JsonCodec.stringify(body), StandardCharsets.UTF_8));
        }
        try {
            HttpResponse<InputStream> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] bytes;
            try (InputStream input = response.body()) {
                bytes = input.readNBytes(maxResponseBytes + 1);
            }
            if (bytes.length > maxResponseBytes) throw protocol("Worker response exceeds limit", null);
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                String detail = "";
                try {
                    Map<String, Object> error = JsonCodec.parseObject(decodeUtf8(bytes));
                    if (error.get("code") instanceof String code
                            && code.matches("[A-Z][A-Z0-9_]{1,127}")) {
                        detail = " (" + code + ")";
                    }
                    if (error.get("message") instanceof String message
                            && message.length() <= 256
                            && message.chars().allMatch(c -> c >= 0x20 && c != 0x7f)) {
                        detail += ": " + message;
                    }
                } catch (RuntimeException ignored) {
                    // Preserve the status-only error if the body is not contract JSON.
                }
                throw new WorkerClientException("HTTP_ERROR", response.statusCode(),
                        "Worker control plane returned HTTP " + response.statusCode() + detail, null);
            }
            String contentType = response.headers().firstValue("Content-Type").orElse("")
                    .toLowerCase(Locale.ROOT);
            if (!contentType.contains("application/json")) {
                throw protocol("Worker response content type is not JSON", null);
            }
            try {
                return JsonCodec.parseObject(decodeUtf8(bytes));
            } catch (RuntimeException invalid) {
                throw protocol("Worker response is malformed JSON", invalid);
            }
        } catch (HttpTimeoutException failure) {
            throw new WorkerClientException("TIMEOUT", 0, "Worker control request timed out", failure);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new WorkerClientException("INTERRUPTED", 0, "Worker control request interrupted", failure);
        } catch (IOException failure) {
            throw new WorkerClientException("TRANSPORT_ERROR", 0, "Worker control transport failed", failure);
        }
    }

    private static TaskDescriptor parseTask(Map<String, Object> root) {
        if (!root.keySet().equals(SNAPSHOT_FIELDS)) {
            throw protocol("task response fields do not match the contract", null);
        }
        requireVersions(root);
        TaskScope scope = parseScope(root);
        TaskLifecycle lifecycle = enumValue(TaskLifecycle.class, string(root, "lifecycle"), "lifecycle");
        if (!string(root, "status").equals(lifecycle.name())) throw protocol("task status mismatch", null);
        WorkerLease lease = root.get("lease") == null ? null : parseLease(object(root.get("lease"), "lease"));
        if (lease != null && !lease.scope().equals(scope)) throw protocol("lease scope mismatch", null);
        boolean active = Set.of(TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED).contains(lifecycle);
        boolean terminal = Set.of(TaskLifecycle.COMPLETED, TaskLifecycle.CANCELLED, TaskLifecycle.FAILED)
                .contains(lifecycle);
        if (active != (lease != null) || terminal && lease != null) {
            throw protocol("task lease does not match lifecycle", null);
        }
        if (root.get("checkpoint") != null) validateCheckpoint(object(root.get("checkpoint"), "checkpoint"), scope);
        String stopReason = optionalString(root, "stopReason");
        String failureCode = optionalString(root, "failureCode");
        if (stopReason != null) enumValue(StopReason.class, stopReason, "stopReason");
        if ((lifecycle == TaskLifecycle.FAILED) != (failureCode != null)) {
            throw protocol("task failure fields do not match lifecycle", null);
        }
        if (failureCode != null) WorkerContracts.id(failureCode, "failureCode");

        WorkerCapability capability =
                enumValue(WorkerCapability.class, string(root, "requiredCapability"), "requiredCapability");
        ResourceBudget resourceBudget = parseResourceBudget(object(root.get("resourceBudget"), "resourceBudget"));
        NetworkPolicy networkPolicy = parseNetworkPolicy(object(root.get("networkPolicy"), "networkPolicy"));
        if (bool(root, "fixtureOnly")) {
            throw protocol("controlled fixture tasks are no longer supported", null);
        }
        String expectedMode = capability == WorkerCapability.STATIC_ONLY
                ? "DYNAMIC_DISABLED"
                : capability.name() + (lifecycle == TaskLifecycle.QUEUED
                ? "_QUEUED" : "_WORKER_MANAGED");
        if (!expectedMode.equals(string(root, "dynamicExecutionMode"))) {
            throw protocol("dynamic execution mode mismatch", null);
        }
        return new TaskDescriptor(scope, lifecycle, string(root, "targetEntryId"),
                bool(root, "authorized"), bool(root, "fixtureOnly"), capability,
                resourceBudget, networkPolicy, lease, instant(root, "updatedAt"));
    }

    private static WorkerLease parseLease(Map<String, Object> root) {
        requireExactFields(root, LEASE_FIELDS, "lease response");
        requireVersions(root);
        return new WorkerLease(CONTRACT_VERSION, parseScope(root), string(root, "leaseId"),
                string(root, "workerId"),
                enumValue(WorkerCapability.class, string(root, "capability"), "capability"),
                instant(root, "issuedAt"), instant(root, "heartbeatAt"), instant(root, "expiresAt"));
    }

    private static ResourceBudget parseResourceBudget(Map<String, Object> root) {
        requireExactFields(root, Set.of("maxWallClockSeconds", "maxCpuMillis", "maxMemoryBytes",
                "maxDiskBytes", "maxTraceBytes"), "resourceBudget");
        return new ResourceBudget(integer(root, "maxWallClockSeconds"), integer(root, "maxCpuMillis"),
                integer(root, "maxMemoryBytes"), integer(root, "maxDiskBytes"),
                integer(root, "maxTraceBytes"));
    }

    private static NetworkPolicy parseNetworkPolicy(Map<String, Object> root) {
        requireExactFields(root, Set.of("mode", "allowlist"), "networkPolicy");
        Object rawAllowlist = root.get("allowlist");
        if (!(rawAllowlist instanceof List<?> values)
                || values.size() > WorkerContracts.MAX_COLLECTION_SIZE
                || values.stream().anyMatch(value -> !(value instanceof String))) {
            throw protocol("networkPolicy allowlist must be a bounded string array", null);
        }
        @SuppressWarnings("unchecked")
        List<String> allowlist = (List<String>) values;
        return new NetworkPolicy(enumValue(NetworkMode.class, string(root, "mode"), "networkPolicy.mode"),
                allowlist);
    }

    private static void validateCheckpoint(Map<String, Object> root, TaskScope expectedScope) {
        requireExactFields(root, Set.of(
                "schemaVersion", "workerContractVersion", "projectId", "artifactDigest", "scanId", "taskId",
                "checkpointId", "traceSequence", "traceHeadDigest", "createdAt"), "checkpoint");
        requireVersions(root);
        requireScope(root, expectedScope);
        WorkerContracts.id(string(root, "checkpointId"), "checkpointId");
        if (integer(root, "traceSequence") < 0) throw protocol("checkpoint sequence is negative", null);
        String digest = optionalString(root, "traceHeadDigest");
        if (digest != null) WorkerContracts.digest(digest, "traceHeadDigest");
        instant(root, "createdAt");
    }

    private static Map<String, Object> scopeBody(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("projectId", scope.projectId());
        result.put("artifactDigest", scope.artifactDigest());
        result.put("scanId", scope.scanId());
        result.put("taskId", scope.taskId());
        return result;
    }

    private static TaskScope parseScope(Map<String, Object> root) {
        return new TaskScope(string(root, "projectId"), string(root, "artifactDigest"),
                string(root, "scanId"), string(root, "taskId"));
    }

    private static void requireScope(Map<String, Object> root, TaskScope expected) {
        if (!parseScope(root).equals(expected)) throw new SecurityException("Worker response scope mismatch");
    }

    private static void requireVersions(Map<String, Object> root) {
        if (integer(root, "schemaVersion") != CONTRACT_VERSION
                || integer(root, "workerContractVersion") != CONTRACT_VERSION) {
            throw protocol("unsupported Worker contract version", null);
        }
    }

    private static void requireExactFields(Map<String, Object> root, Set<String> fields, String name) {
        if (!root.keySet().equals(fields)) throw protocol(name + " fields do not match the contract", null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String name) {
        if (!(value instanceof Map<?, ?> map)) throw protocol(name + " must be an object", null);
        return (Map<String, Object>) map;
    }

    private static String string(Map<String, Object> root, String name) {
        Object value = root.get(name);
        if (!(value instanceof String text) || text.isBlank() || text.length() > 4096) {
            throw protocol(name + " must be a bounded string", null);
        }
        return text;
    }

    private static String optionalString(Map<String, Object> root, String name) {
        return root.get(name) == null ? null : string(root, name);
    }

    private static boolean bool(Map<String, Object> root, String name) {
        Object value = root.get(name);
        if (!(value instanceof Boolean result)) throw protocol(name + " must be boolean", null);
        return result;
    }

    private static long integer(Map<String, Object> root, String name) {
        Object value = root.get(name);
        if (!(value instanceof Number number) || number.doubleValue() != number.longValue()) {
            throw protocol(name + " must be an integer", null);
        }
        return number.longValue();
    }

    private static Instant instant(Map<String, Object> root, String name) {
        try {
            return Instant.parse(string(root, name));
        } catch (DateTimeParseException invalid) {
            throw protocol(name + " must be an instant", invalid);
        }
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value, String name) {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException invalid) {
            throw protocol(name + " is unsupported", invalid);
        }
    }

    private URI resolve(String relative) {
        URI result = baseUri.resolve(relative);
        if (!sameOrigin(baseUri, result)) throw new SecurityException("cross-origin Worker URI rejected");
        return result;
    }

    private static URI safeBase(URI value) {
        Objects.requireNonNull(value, "baseUri");
        if (!("http".equalsIgnoreCase(value.getScheme()) || "https".equalsIgnoreCase(value.getScheme()))
                || value.getHost() == null || value.getRawUserInfo() != null
                || value.getRawQuery() != null || value.getRawFragment() != null) {
            throw new IllegalArgumentException("baseUri must be a safe absolute HTTP URI");
        }
        String path = value.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        if (!path.endsWith("/")) path += "/";
        URI result = URI.create(value.getScheme() + "://" + value.getRawAuthority() + path).normalize();
        if (!result.getRawPath().endsWith("/internal/worker/v1/")) {
            throw new IllegalArgumentException("baseUri must target /internal/worker/v1/");
        }
        return result;
    }

    private static boolean sameOrigin(URI left, URI right) {
        return left.getScheme().equalsIgnoreCase(right.getScheme())
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException invalid) {
            throw protocol("Worker response is not valid UTF-8", invalid);
        }
    }

    private static String idempotency(TaskScope scope, String action, String suffix) {
        String material = scope.projectId() + "\n" + scope.artifactDigest() + "\n" + scope.scanId()
                + "\n" + scope.taskId() + "\n" + action + "\n" + suffix;
        return "worker-" + WorkerContracts.sha256(material.getBytes(StandardCharsets.UTF_8));
    }

    private static String secret(String value) {
        Objects.requireNonNull(value, "workerToken");
        if (value.isBlank() || value.length() > 4096
                || value.chars().anyMatch(c -> c < 0x21 || c == 0x7f)) {
            throw new IllegalArgumentException("invalid workerToken");
        }
        return value;
    }

    private static WorkerClientException protocol(String message, Throwable cause) {
        return new WorkerClientException("PROTOCOL_ERROR", 0, message, cause);
    }

    public record TaskDescriptor(TaskScope scope, TaskLifecycle lifecycle, String targetEntryId,
                                 boolean authorized, boolean fixtureOnly,
                                 WorkerCapability requiredCapability, ResourceBudget resourceBudget,
                                 NetworkPolicy networkPolicy,
                                 WorkerLease lease, Instant updatedAt) {
        public TaskDescriptor {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(lifecycle, "lifecycle");
            WorkerContracts.id(targetEntryId, "targetEntryId");
            Objects.requireNonNull(requiredCapability, "requiredCapability");
            Objects.requireNonNull(resourceBudget, "resourceBudget");
            Objects.requireNonNull(networkPolicy, "networkPolicy");
            Objects.requireNonNull(updatedAt, "updatedAt");
        }
    }

    public record TraceCommit(long sequence, String digest, String traceHeadDigest,
                              long totalPayloadBytes) { }

    public static final class WorkerClientException extends RuntimeException {
        private final String code;
        private final int statusCode;

        private WorkerClientException(String code, int statusCode, String message, Throwable cause) {
            super(message, cause);
            this.code = code;
            this.statusCode = statusCode;
        }

        public String code() { return code; }
        public int statusCode() { return statusCode; }
    }
}
