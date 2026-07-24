package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Production HTTPS-only, no-redirect transport for bounded provider chat calls. */
public final class ProviderChatTransport implements ChatTransport {
    private static final int MAX_KEY_BYTES = 4_096;
    private final HttpClient client;

    public ProviderChatTransport() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    ProviderChatTransport(HttpClient client) {
        this.client = Objects.requireNonNull(client, "client");
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("provider chat transport must not follow redirects");
        }
    }

    @Override
    public Response send(ProviderDefinition provider, byte[] credential, JsonNode requestBody,
                         Limits limits) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(requestBody, "requestBody");
        Objects.requireNonNull(limits, "limits");
        if (!provider.enabled() || !provider.credentialConfigured()) {
            throw failure("PROVIDER_NOT_READY");
        }
        if (provider.kind() != ProviderKind.OPENAI_CHAT
                && provider.kind() != ProviderKind.ANTHROPIC_MESSAGES
                && provider.kind() != ProviderKind.OPENAI_COMPATIBLE) {
            throw failure("PROVIDER_PROTOCOL_UNSUPPORTED");
        }
        URI base = ProviderContracts.validatedEndpoint(provider.endpoint(), provider.kind());
        if (!"https".equalsIgnoreCase(base.getScheme())) {
            throw failure("HTTPS_REQUIRED");
        }
        ProviderProtocol protocol = provider.kind().protocol();
        URI target = endpoint(base, protocol);
        byte[] key = Objects.requireNonNull(credential, "credential").clone();
        byte[] body = encode(requestBody, limits.maxRequestBytes());
        String headerSecret = decodeSecret(key);
        long started = System.nanoTime();
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                    .timeout(limits.requestTimeout())
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            if (protocol == ProviderProtocol.OPENAI_CHAT) {
                builder.header("Authorization", "Bearer " + headerSecret);
            } else {
                builder.header("x-api-key", headerSecret)
                        .header("anthropic-version", "2023-06-01");
            }
            HttpResponse<InputStream> response;
            try {
                response = client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw failure("REQUEST_CANCELLED");
            } catch (IOException | RuntimeException transportFailure) {
                throw failure("TRANSPORT_FAILED");
            }
            if (!target.equals(response.uri())) {
                close(response.body());
                throw failure("REDIRECT_REJECTED");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                close(response.body());
                throw failure("HTTP_" + response.statusCode());
            }
            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (!contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
                close(response.body());
                throw failure("INVALID_CONTENT_TYPE");
            }
            long declared = response.headers().firstValueAsLong("Content-Length").orElse(0);
            if (declared > limits.maxResponseBytes()) {
                close(response.body());
                throw failure("RESPONSE_TOO_LARGE");
            }
            byte[] responseBody = readBounded(
                    response.body(), limits.maxResponseBytes(), limits.requestTimeout());
            String requestId = response.headers().firstValue("x-request-id")
                    .or(() -> response.headers().firstValue("request-id")).orElse(null);
            if (requestId != null && (requestId.length() > 256
                    || requestId.chars().anyMatch(Character::isISOControl))) requestId = null;
            try {
                return new Response(response.statusCode(), responseBody, requestId,
                        Duration.ofNanos(System.nanoTime() - started).toMillis());
            } finally {
                Arrays.fill(responseBody, (byte) 0);
            }
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(body, (byte) 0);
            headerSecret = null;
        }
    }

    private static URI endpoint(URI base, ProviderProtocol protocol) {
        String path = protocol == ProviderProtocol.OPENAI_CHAT
                ? "/v1/chat/completions" : "/v1/messages";
        try {
            return new URI("https", null, base.getHost(), base.getPort(), path, null, null);
        } catch (Exception impossible) {
            throw failure("INVALID_ENDPOINT");
        }
    }

    private static byte[] encode(JsonNode body, int maximum) {
        try {
            byte[] encoded = ChatProtocolSupport.JSON.writeValueAsBytes(body);
            if (encoded.length > maximum) {
                Arrays.fill(encoded, (byte) 0);
                throw failure("REQUEST_TOO_LARGE");
            }
            return encoded;
        } catch (TransportException expected) {
            throw expected;
        } catch (Exception invalid) {
            throw failure("REQUEST_ENCODING_FAILED");
        }
    }

    private static String decodeSecret(byte[] secret) {
        if (secret.length == 0 || secret.length > MAX_KEY_BYTES) throw failure("INVALID_CREDENTIAL");
        try {
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(secret)).toString();
            if (value.isBlank() || value.chars().anyMatch(Character::isISOControl)) {
                throw failure("INVALID_CREDENTIAL");
            }
            return value;
        } catch (CharacterCodingException invalid) {
            throw failure("INVALID_CREDENTIAL");
        }
    }

    private static byte[] readBounded(InputStream input, int maximum, Duration timeout) {
        AtomicBoolean timedOut = new AtomicBoolean();
        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "provider-chat-body-timeout");
            thread.setDaemon(true);
            return thread;
        });
        var timeoutTask = timer.schedule(() -> {
            timedOut.set(true);
            close(input);
        }, timeout.toMillis(), TimeUnit.MILLISECONDS);
        try (InputStream body = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8_192];
            int total = 0;
            int read;
            while ((read = body.read(buffer)) != -1) {
                total += read;
                if (total > maximum) throw failure("RESPONSE_TOO_LARGE");
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } catch (TransportException expected) {
            throw expected;
        } catch (IOException failure) {
            throw failure(timedOut.get() ? "RESPONSE_TIMEOUT" : "RESPONSE_READ_FAILED");
        } finally {
            timeoutTask.cancel(false);
            timer.shutdownNow();
        }
    }

    private static void close(InputStream input) {
        try {
            if (input != null) input.close();
        } catch (IOException ignored) {
            // Rejected response.
        }
    }

    private static TransportException failure(String code) {
        return new TransportException(code);
    }

    public record Limits(Duration requestTimeout, int maxRequestBytes, int maxResponseBytes) {
        public Limits {
            Objects.requireNonNull(requestTimeout, "requestTimeout");
            if (requestTimeout.isZero() || requestTimeout.isNegative()
                    || requestTimeout.compareTo(Duration.ofMinutes(2)) > 0) {
                throw new IllegalArgumentException("requestTimeout is invalid");
            }
            if (maxRequestBytes < 1 || maxRequestBytes > ProviderChatContracts.MAX_REQUEST_BYTES
                    || maxResponseBytes < 1 || maxResponseBytes > ProviderChatContracts.MAX_RESPONSE_BYTES) {
                throw new IllegalArgumentException("transport byte limit is invalid");
            }
        }
    }

    public record Response(int statusCode, byte[] body, String requestId, long elapsedMillis) {
        public Response {
            if (statusCode < 100 || statusCode > 599) throw new IllegalArgumentException("invalid status");
            body = Objects.requireNonNull(body, "body").clone();
            if (elapsedMillis < 0) throw new IllegalArgumentException("elapsedMillis is invalid");
        }

        @Override public byte[] body() { return body.clone(); }
        public void clear() { Arrays.fill(body, (byte) 0); }
    }

    public static final class TransportException extends RuntimeException {
        private final String code;
        public TransportException(String code) {
            super(code, null, false, false);
            this.code = code;
        }
        public String code() { return code; }
    }
}
