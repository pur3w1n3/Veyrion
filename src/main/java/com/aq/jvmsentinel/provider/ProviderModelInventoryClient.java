package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.provider.ProviderContracts.InventorySemantics;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * 有界、仅 inventory 的 client，面向 OpenAI Chat Completions 与 Anthropic Messages provider。
 * 本类刻意没有任何执行 model request 的方法。
 */
public final class ProviderModelInventoryClient {
    static final int MAX_MODELS = 1_000;
    static final int MAX_PAGES = 20;
    static final int PAGE_SIZE = 100;
    static final int MAX_PAGE_BYTES = 1_048_576;
    static final int MAX_TOTAL_BYTES = 4 * MAX_PAGE_BYTES;
    private static final int MAX_MODEL_NAME = 512;
    private static final int MAX_CURSOR = 512;
    private static final int MAX_API_KEY_BYTES = 4_096;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final boolean loopbackHttpForTests;

    public ProviderModelInventoryClient() {
        this(HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(5))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                secureMapper(), Clock.systemUTC(), false);
    }

    ProviderModelInventoryClient(HttpClient client, Clock clock, boolean loopbackHttpForTests) {
        this(client, secureMapper(), clock, loopbackHttpForTests);
    }

    private ProviderModelInventoryClient(HttpClient client, ObjectMapper mapper, Clock clock,
                                         boolean loopbackHttpForTests) {
        this.client = Objects.requireNonNull(client, "client");
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("provider client must not follow redirects");
        }
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.loopbackHttpForTests = loopbackHttpForTests;
    }

    public ModelInventory fetch(ProviderDefinition provider, byte[] apiKey) {
        Objects.requireNonNull(provider, "provider");
        return fetch(provider.workspaceId(), provider.providerId(), provider.kind(),
                provider.endpoint(), apiKey);
    }

    ModelInventory fetchForLoopbackTest(String workspaceId, String providerId, ProviderKind kind,
                                        URI endpoint, byte[] apiKey) {
        if (!loopbackHttpForTests) {
            throw new IllegalStateException("loopback HTTP test transport is disabled");
        }
        return fetch(workspaceId, providerId, kind, endpoint, apiKey);
    }

    private ModelInventory fetch(String workspaceId, String providerId, ProviderKind kind,
                                 URI endpoint, byte[] apiKey) {
        Objects.requireNonNull(kind, "kind");
        ProviderProtocol protocol = kind.protocol();
        URI base = validateTransportEndpoint(endpoint, kind);
        byte[] secret = Objects.requireNonNull(apiKey, "apiKey").clone();
        String headerSecret = decodeSecret(secret);
        try {
            Instant fetchedAt = clock.instant();
            List<ModelDefinition> models = new ArrayList<>();
            Set<String> names = new HashSet<>();
            String cursor = null;
            int totalBytes = 0;
            for (int page = 0; page < MAX_PAGES; page++) {
                URI requestUri = modelsUri(base, protocol, cursor);
                HttpRequest request = request(requestUri, protocol, headerSecret);
                HttpResponse<InputStream> response = send(request);
                if (!requestUri.equals(response.uri())) {
                    closeQuietly(response.body());
                    throw failure("provider redirect was rejected");
                }
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    closeQuietly(response.body());
                    throw failure("provider returned HTTP " + response.statusCode());
                }
                String contentType = response.headers().firstValue("Content-Type").orElse("");
                if (!contentType.toLowerCase(java.util.Locale.ROOT).startsWith("application/json")) {
                    closeQuietly(response.body());
                    throw failure("provider response content type is invalid");
                }
                int remaining = MAX_TOTAL_BYTES - totalBytes;
                int pageLimit = Math.min(MAX_PAGE_BYTES, remaining);
                if (response.headers().firstValueAsLong("Content-Length").orElse(0) > pageLimit) {
                    closeQuietly(response.body());
                    throw failure("provider response exceeds size limit");
                }
                byte[] body = readBounded(response.body(), pageLimit);
                totalBytes += body.length;
                Page parsed = parsePage(body);
                for (String name : parsed.modelNames()) {
                    if (!names.add(name)) {
                        throw failure("provider returned a duplicate model identifier");
                    }
                    if (models.size() == MAX_MODELS) {
                        throw failure("provider model inventory exceeds limit");
                    }
                    models.add(new ModelDefinition(ProviderContracts.SCHEMA_VERSION, workspaceId,
                            inventoryId(providerId, name), providerId, name, 0, false,
                            fetchedAt, fetchedAt));
                }
                if (!parsed.hasMore()) {
                    return new ModelInventory(ProviderContracts.SCHEMA_VERSION, workspaceId,
                            providerId, protocol, models, InventorySemantics.REMOTE_INVENTORY_ONLY,
                            fetchedAt);
                }
                if (parsed.nextCursor() == null || parsed.nextCursor().equals(cursor)) {
                    throw failure("provider pagination cursor is missing or did not advance");
                }
                cursor = parsed.nextCursor();
            }
            throw failure("provider pagination exceeds limit");
        } finally {
            Arrays.fill(secret, (byte) 0);
            // HttpRequest 需要 immutable String header value。永不保留于 DTO、
            // exception、audit record 或 result；caller-owned byte array 仍归 caller。
            headerSecret = null;
        }
    }

    private URI validateTransportEndpoint(URI endpoint, ProviderKind kind) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (loopbackHttpForTests && "http".equalsIgnoreCase(endpoint.getScheme())
                && isLoopback(endpoint.getHost()) && endpoint.isAbsolute()
                && endpoint.getRawUserInfo() == null && endpoint.getRawQuery() == null
                && endpoint.getRawFragment() == null) {
            return endpoint.normalize();
        }
        return ProviderContracts.validatedEndpoint(endpoint, kind);
    }

    private static HttpRequest request(URI uri, ProviderProtocol protocol, String apiKey) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json")
                .GET();
        if (protocol == ProviderProtocol.OPENAI_CHAT) {
            builder.header("Authorization", "Bearer " + apiKey);
        } else {
            builder.header("x-api-key", apiKey)
                    .header("anthropic-version", "2023-06-01");
        }
        return builder.build();
    }

    private HttpResponse<InputStream> send(HttpRequest request) {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw failure("provider inventory request was interrupted");
        } catch (IOException | RuntimeException transportFailure) {
            throw failure("provider inventory request failed");
        }
    }

    private Page parsePage(byte[] body) {
        try {
            JsonNode root = mapper.readTree(body);
            if (root == null || !root.isObject()) {
                throw failure("provider response must be a JSON object");
            }
            JsonNode data = root.get("data");
            if (data == null || !data.isArray()) {
                throw failure("provider response data must be an array");
            }
            List<String> names = new ArrayList<>();
            for (JsonNode model : data) {
                if (!model.isObject()) {
                    throw failure("provider model entry must be an object");
                }
                JsonNode id = model.get("id");
                if (id == null || !id.isTextual()) {
                    throw failure("provider model id must be a string");
                }
                names.add(boundedText(id.textValue(), "provider model id", MAX_MODEL_NAME));
                if (names.size() > MAX_MODELS) {
                    throw failure("provider model page exceeds limit");
                }
            }
            JsonNode hasMoreNode = root.get("has_more");
            boolean hasMore = false;
            if (hasMoreNode != null) {
                if (!hasMoreNode.isBoolean()) {
                    throw failure("provider has_more must be boolean");
                }
                hasMore = hasMoreNode.booleanValue();
            }
            String cursor = null;
            JsonNode lastId = root.get("last_id");
            if (lastId != null && !lastId.isNull()) {
                if (!lastId.isTextual()) {
                    throw failure("provider last_id must be a string");
                }
                cursor = boundedText(lastId.textValue(), "provider last_id", MAX_CURSOR);
            }
            if (hasMore && cursor == null) {
                throw failure("provider pagination cursor is missing");
            }
            return new Page(List.copyOf(names), hasMore, cursor);
        } catch (ProviderAccessException expected) {
            throw expected;
        } catch (IOException | RuntimeException malformed) {
            throw failure("provider response JSON is invalid");
        }
    }

    private static byte[] readBounded(InputStream input, int limit) {
        if (limit <= 0) {
            closeQuietly(input);
            throw failure("provider response exceeds total size limit");
        }
        ScheduledExecutorService bodyTimeout = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "provider-body-timeout");
            thread.setDaemon(true);
            return thread;
        });
        ScheduledFuture<?> timeout = bodyTimeout.schedule(
                () -> closeQuietly(input), REQUEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        try (InputStream body = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8_192];
            int read;
            int total = 0;
            while ((read = body.read(buffer)) != -1) {
                total += read;
                if (total > limit) {
                    throw failure("provider response exceeds size limit");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } catch (ProviderAccessException expected) {
            throw expected;
        } catch (IOException readFailure) {
            throw failure("provider response could not be read");
        } finally {
            timeout.cancel(false);
            bodyTimeout.shutdownNow();
        }
    }

    private static URI modelsUri(URI base, ProviderProtocol protocol, String cursor) {
        String basePath = base.getRawPath();
        if (basePath == null || basePath.equals("/")) basePath = "";
        while (basePath.endsWith("/")) basePath = basePath.substring(0, basePath.length() - 1);
        String suffix = protocol.modelsPath();
        String path = basePath.endsWith("/v1") ? basePath + "/models" : basePath + suffix;
        String query = "limit=" + PAGE_SIZE;
        if (cursor != null) {
            query += "&" + protocol.cursorParameter() + "="
                    + URLEncoder.encode(cursor, StandardCharsets.UTF_8);
        }
        try {
            return new URI(base.getScheme(), null, base.getHost(), base.getPort(), path, query, null);
        } catch (Exception impossible) {
            throw failure("provider models endpoint could not be constructed");
        }
    }

    private static String decodeSecret(byte[] secret) {
        if (secret.length == 0 || secret.length > MAX_API_KEY_BYTES) {
            throw failure("provider credential is invalid");
        }
        try {
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(secret)).toString();
            if (value.isBlank() || value.chars().anyMatch(Character::isISOControl)) {
                throw failure("provider credential is invalid");
            }
            return value;
        } catch (CharacterCodingException invalid) {
            throw failure("provider credential is invalid");
        }
    }

    private static String boundedText(String value, String field, int maximum) {
        if (value == null || value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(Character::isISOControl)) {
            throw failure(field + " is invalid");
        }
        return value;
    }

    private static String inventoryId(String providerId, String modelName) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(providerId.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(modelName.getBytes(StandardCharsets.UTF_8));
            return "inventory-" + HexFormat.of().formatHex(digest.digest());
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 is unavailable");
        }
    }

    private static ObjectMapper secureMapper() {
        StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxNestingDepth(16)
                .maxStringLength(MAX_PAGE_BYTES)
                .maxNumberLength(64)
                .maxNameLength(256)
                .build();
        return new ObjectMapper(JsonFactory.builder().streamReadConstraints(constraints).build());
    }

    private static boolean isLoopback(String host) {
        return host != null && ("localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host) || "::1".equals(host)
                || "0:0:0:0:0:0:0:1".equals(host));
    }

    private static void closeQuietly(InputStream body) {
        if (body == null) return;
        try {
            body.close();
        } catch (IOException ignored) {
            // response 已在拒绝流程中。
        }
    }

    private static ProviderAccessException failure(String message) {
        return new ProviderAccessException(message);
    }

    private record Page(List<String> modelNames, boolean hasMore, String nextCursor) { }

    public static final class ProviderAccessException extends RuntimeException {
        private ProviderAccessException(String message) {
            super(message, null, false, false);
        }
    }
}
