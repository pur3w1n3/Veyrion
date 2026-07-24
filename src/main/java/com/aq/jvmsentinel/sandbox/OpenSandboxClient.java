package com.aq.jvmsentinel.sandbox;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.worker.ResourceBudget;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Dependency-free, fail-closed OpenSandbox lifecycle and Execd protocol adapter. */
public final class OpenSandboxClient {
    private static final Set<String> SAFE_ENDPOINT_HEADERS = Set.of(
            "x-opensandbox-access-token", "x-opensandbox-endpoint-token");
    private final OpenSandboxConfig config;
    private final HttpClient http;
    private final Map<String, SandboxRequest> expectations = new ConcurrentHashMap<>();

    public OpenSandboxClient(OpenSandboxConfig config) {
        this(config, HttpClient.newBuilder().connectTimeout(config.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    public OpenSandboxClient(OpenSandboxConfig config, HttpClient http) {
        this.config = java.util.Objects.requireNonNull(config, "config");
        this.http = java.util.Objects.requireNonNull(http, "http");
    }

    public SandboxHandle create(SandboxRequest request) {
        java.util.Objects.requireNonNull(request, "request");
        // Attestation is deployment-owned configuration, so reject missing capability before creating anything.
        config.runtimeAttestation().require(config, request);
        if (!request.fixtureOnly() && request.readOnlyArtifacts().size() != 1) {
            throw OpenSandboxException.capability(
                    "external artifact requires one digest-pinned read-only mount");
        }
        Response response = sendLifecycle("POST", "sandboxes", createBody(request));
        requireStatus(response, 202);
        SandboxHandle handle = parseHandle(response.body(), config.runtimeAttestation());
        SandboxRequest previous = expectations.putIfAbsent(handle.id(), request);
        if (previous != null && !previous.equals(request)) {
            throw OpenSandboxException.capability("sandbox identifier was reused with different policy");
        }
        return handle;
    }

    public SandboxHandle get(String sandboxId) {
        String id = SandboxContracts.id(sandboxId, "sandboxId");
        SandboxRequest expected = requireExpectation(id);
        Response response = sendLifecycle("GET", "sandboxes/" + id, null);
        requireStatus(response, 200);
        return validatedHandle(response, expected, id);
    }

    public SandboxHandle pause(String sandboxId) {
        return transition(sandboxId, "pause");
    }

    public SandboxHandle resume(String sandboxId) {
        return transition(sandboxId, "resume");
    }

    public void delete(String sandboxId) {
        String id = SandboxContracts.id(sandboxId, "sandboxId");
        requireExpectation(id);
        Response response = sendLifecycle("DELETE", "sandboxes/" + id, null);
        requireStatus(response, 200, 202, 204);
        expectations.remove(id);
    }

    public CommandResult command(String sandboxId, CommandRequest request) {
        String id = SandboxContracts.id(sandboxId, "sandboxId");
        requireExpectation(id);
        java.util.Objects.requireNonNull(request, "request");
        ExecdEndpoint endpoint = resolveExecdEndpoint(id);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command", request.command());
        body.put("cwd", request.workingDirectory());
        body.put("background", false);
        body.put("timeout", request.timeout().toMillis());
        body.put("uid", request.uid());
        body.put("gid", request.gid());
        Response response = send("POST", endpoint.commandUri(), body,
                "X-EXECD-ACCESS-TOKEN", config.execdAccessToken(), endpoint.headers());
        requireStatus(response, 200);
        String contentType = response.contentType().toLowerCase(Locale.ROOT);
        return contentType.contains("text/event-stream") ? parseCommandEvents(response.body())
                : parseCommandJson(response.body());
    }

    private SandboxHandle transition(String sandboxId, String action) {
        String id = SandboxContracts.id(sandboxId, "sandboxId");
        SandboxRequest expected = requireExpectation(id);
        Response response = sendLifecycle("POST", "sandboxes/" + id + "/" + action, null);
        requireStatus(response, 200, 202);
        return validatedHandle(response, expected, id);
    }

    private SandboxHandle validatedHandle(Response response, SandboxRequest expected, String expectedId) {
        SandboxHandle handle = parseHandle(response.body(), config.runtimeAttestation());
        if (!handle.id().equals(expectedId)) throw OpenSandboxException.protocol("sandbox id mismatch", null);
        handle.runtimeAttestation().require(config, expected);
        return handle;
    }

    private SandboxRequest requireExpectation(String id) {
        SandboxRequest request = expectations.get(id);
        if (request == null) throw OpenSandboxException.capability("sandbox policy is not known to this client");
        return request;
    }

    private Map<String, Object> createBody(SandboxRequest request) {
        ResourceBudget budget = request.resourceBudget();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("image", Map.of("uri", request.image()));
        body.put("timeout", request.timeoutSeconds());
        body.put("resourceLimits", Map.of(
                "cpu", "1000m",
                "memory", budget.maxMemoryBytes() + "B",
                "ephemeral-storage", budget.maxDiskBytes() + "B"));
        body.put("entrypoint", request.entrypoint());
        body.put("networkPolicy", Map.of("defaultAction", "deny", "egress", List.of()));
        body.put("tmpfs", List.of(Map.of(
                "destination", "/tmp",
                "sizeBytes", request.tmpfsBytes(),
                "mode", "0700",
                "uid", 10000,
                "gid", 10000)));
        if (!request.readOnlyArtifacts().isEmpty()) {
            body.put("readOnlyArtifacts", request.readOnlyArtifacts().stream().map(mount -> Map.of(
                    "sourceRef", "sha256:" + mount.sha256(),
                    "destination", mount.destination(),
                    "sha256", mount.sha256(),
                    "sizeBytes", mount.sizeBytes(),
                    "readOnly", true,
                    "verifyBeforeStart", true)).toList());
        }
        Map<String, String> extensions = new LinkedHashMap<>();
        extensions.putAll(Map.of(
                "veyrion.protocolVersion", config.requiredProtocolVersion(),
                "veyrion.requiredCapability", request.requiredCapability().name(),
                "veyrion.fixtureOnly", Boolean.toString(request.fixtureOnly()),
                "veyrion.maxCpuMillis", Long.toString(budget.maxCpuMillis()),
                "veyrion.maxTraceBytes", Long.toString(budget.maxTraceBytes()),
                "veyrion.readOnlyRootFilesystem", "true",
                "veyrion.controlledTmpfs", "true",
                "veyrion.writableTmp", "true",
                "veyrion.nonRoot", "true"));
        if (!request.readOnlyArtifacts().isEmpty()) {
            ReadOnlyArtifactMount mount = request.readOnlyArtifacts().get(0);
            extensions.put("veyrion.artifactSha256", mount.sha256());
            extensions.put("veyrion.artifactReadOnly", "true");
            extensions.put("veyrion.artifactVerifyBeforeStart", "true");
        }
        body.put("extensions", extensions);
        return body;
    }

    private Response sendLifecycle(String method, String path, Map<String, Object> body) {
        return send(method, SandboxContracts.resolve(config.lifecycleBaseUri(), path), body,
                "OPEN-SANDBOX-API-KEY", config.apiKey(), Map.of());
    }

    private ExecdEndpoint resolveExecdEndpoint(String sandboxId) {
        Response response = sendLifecycle("GET", "sandboxes/" + sandboxId + "/endpoints/44772", null);
        requireStatus(response, 200);
        try {
            Map<String, Object> root = JsonCodec.parseObject(response.body());
            if (!root.containsKey("endpoint") || !Set.of("endpoint", "headers").containsAll(root.keySet())) {
                throw new IllegalArgumentException("endpoint response fields are invalid");
            }
            URI endpoint = endpointUri(string(root, "endpoint"), sandboxId);
            Map<String, String> headers = root.containsKey("headers")
                    ? endpointHeaders(object(root, "headers")) : Map.of();
            return new ExecdEndpoint(commandUri(endpoint), headers);
        } catch (OpenSandboxException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw OpenSandboxException.protocol("malformed endpoint response", exception);
        }
    }

    private Response send(String method, URI uri, Map<String, Object> body,
                          String authenticationHeader, String authenticationValue,
                          Map<String, String> additionalHeaders) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(config.requestTimeout())
                .header("Accept", "application/json, text/event-stream")
                .header(authenticationHeader, authenticationValue);
        for (Map.Entry<String, String> header : additionalHeaders.entrySet()) {
            if (header.getKey().equalsIgnoreCase(authenticationHeader)) {
                throw OpenSandboxException.capability("endpoint header attempted to override authentication");
            }
            builder.header(header.getKey(), header.getValue());
        }
        if (body == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(JsonCodec.stringify(body), StandardCharsets.UTF_8));
        }
        try {
            HttpResponse<InputStream> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] bytes;
            try (InputStream input = response.body()) {
                bytes = input.readNBytes(SandboxContracts.MAX_RESPONSE_BYTES + 1);
                if (bytes.length > SandboxContracts.MAX_RESPONSE_BYTES) {
                    throw new OpenSandboxException("RESPONSE_TOO_LARGE", response.statusCode(),
                            "OpenSandbox response exceeds limit", null);
                }
            }
            return new Response(response.statusCode(), new String(bytes, StandardCharsets.UTF_8),
                    response.headers().firstValue("Content-Type").orElse(""));
        } catch (HttpTimeoutException exception) {
            throw new OpenSandboxException("TIMEOUT", 0, "OpenSandbox request timed out", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new OpenSandboxException("INTERRUPTED", 0, "OpenSandbox request interrupted", exception);
        } catch (IOException exception) {
            throw new OpenSandboxException("TRANSPORT_ERROR", 0, "OpenSandbox transport failed", exception);
        }
    }

    private URI endpointUri(String value, String sandboxId) {
        String bounded = SandboxContracts.text(value, "endpoint", 4096);
        URI endpoint;
        try {
            endpoint = URI.create(bounded);
        } catch (IllegalArgumentException exception) {
            throw OpenSandboxException.protocol("endpoint URI is invalid", exception);
        }
        if (!("http".equalsIgnoreCase(endpoint.getScheme()) || "https".equalsIgnoreCase(endpoint.getScheme()))
                || endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getRawQuery() != null || endpoint.getRawFragment() != null
                || !endpoint.normalize().equals(endpoint)) {
            throw OpenSandboxException.capability("endpoint URI is not a safe absolute HTTP URI");
        }
        if (!sameOrigin(config.lifecycleBaseUri(), endpoint)) {
            throw OpenSandboxException.capability("execd endpoint is not lifecycle-proxied on the same origin");
        }
        String expectedSuffix = "/sandboxes/" + sandboxId + "/port/44772";
        String path = endpoint.getPath();
        if (path == null || !(path.equals(expectedSuffix) || path.endsWith(expectedSuffix))) {
            throw OpenSandboxException.capability("execd endpoint is not bound to the requested sandbox and port");
        }
        return endpoint;
    }

    private static URI commandUri(URI endpoint) {
        String path = endpoint.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        if (!path.endsWith("/")) path += "/";
        return URI.create(endpoint.getScheme() + "://" + endpoint.getRawAuthority() + path + "command");
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

    private static Map<String, String> endpointHeaders(Map<String, Object> values) {
        if (values.size() > 8) throw new IllegalArgumentException("too many endpoint headers");
        Map<String, String> result = new LinkedHashMap<>();
        Set<String> seen = new java.util.HashSet<>();
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            String normalized = entry.getKey().toLowerCase(Locale.ROOT);
            if (!SAFE_ENDPOINT_HEADERS.contains(normalized) || !seen.add(normalized)) {
                throw OpenSandboxException.capability("endpoint returned a forbidden or duplicate header");
            }
            if (!(entry.getValue() instanceof String value)) {
                throw new IllegalArgumentException("endpoint header value must be a string");
            }
            result.put(canonicalHeader(normalized), SandboxContracts.text(value, "endpoint header value", 4096));
        }
        return Map.copyOf(result);
    }

    private static String canonicalHeader(String normalized) {
        return normalized.equals("x-opensandbox-access-token")
                ? "X-OpenSandbox-Access-Token" : "X-OpenSandbox-Endpoint-Token";
    }

    private static void requireStatus(Response response, int... accepted) {
        for (int status : accepted) if (response.status() == status) return;
        String code = "HTTP_ERROR";
        try {
            Object candidate = JsonCodec.parseObject(response.body()).get("code");
            if (candidate instanceof String value && value.matches("[A-Z][A-Z0-9_]{0,63}")) code = value;
        } catch (RuntimeException ignored) {
            // Error bodies are untrusted and never copied into exception messages.
        }
        throw new OpenSandboxException(code, response.status(),
                "OpenSandbox returned HTTP " + response.status(), null);
    }

    private static SandboxHandle parseHandle(String body, RuntimeAttestation attestation) {
        try {
            Map<String, Object> root = JsonCodec.parseObject(body);
            String id = string(root, "id");
            Map<String, Object> statusValue = object(root, "status");
            SandboxStatus status = new SandboxStatus(parseState(string(statusValue, "state")),
                    optionalString(statusValue, "reason"), optionalString(statusValue, "message"));
            return new SandboxHandle(id, status, attestation);
        } catch (OpenSandboxException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw OpenSandboxException.protocol("malformed sandbox response", exception);
        }
    }

    private static CommandResult parseCommandJson(String body) {
        try {
            Map<String, Object> value = JsonCodec.parseObject(body);
            return new CommandResult(optionalString(value, "id"),
                    optionalString(value, "stdout"), optionalString(value, "stderr"),
                    integer(value, value.containsKey("exitCode") ? "exitCode" : "exit_code"));
        } catch (RuntimeException exception) {
            throw OpenSandboxException.protocol("malformed command response", exception);
        }
    }

    private static CommandResult parseCommandEvents(String body) {
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        String commandId = null;
        Integer exitCode = null;
        try {
            for (String line : body.split("\\r?\\n")) {
                if (!line.startsWith("data:")) continue;
                Map<String, Object> event = JsonCodec.parseObject(line.substring(5).stripLeading());
                String type = string(event, "type");
                String text = optionalString(event, "text");
                if ("stdout".equals(type) && text != null) stdout.append(text);
                if (("stderr".equals(type) || "error".equals(type)) && text != null) stderr.append(text);
                String id = optionalString(event, "id");
                if (id != null) commandId = id;
                if (event.containsKey("exitCode")) exitCode = integer(event, "exitCode");
                if (event.containsKey("exit_code")) exitCode = integer(event, "exit_code");
            }
            if (exitCode == null) throw new IllegalArgumentException("completion exit code is absent");
            return new CommandResult(commandId, stdout.toString(), stderr.toString(), exitCode);
        } catch (RuntimeException exception) {
            throw OpenSandboxException.protocol("malformed command event stream", exception);
        }
    }

    private static SandboxStatus.State parseState(String value) {
        return SandboxStatus.State.valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException(key + " must be an object");
        return (Map<String, Object>) map;
    }

    private static String string(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (!(value instanceof String text)) throw new IllegalArgumentException(key + " must be a string");
        return text;
    }

    private static String optionalString(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (value == null) return null;
        if (!(value instanceof String text)) throw new IllegalArgumentException(key + " must be a string");
        return text;
    }

    private static int integer(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (!(value instanceof Number number) || number.longValue() < Integer.MIN_VALUE
                || number.longValue() > Integer.MAX_VALUE || number.doubleValue() != number.longValue()) {
            throw new IllegalArgumentException(key + " must be an integer");
        }
        return number.intValue();
    }

    private record Response(int status, String body, String contentType) { }
    private record ExecdEndpoint(URI commandUri, Map<String, String> headers) { }
}
