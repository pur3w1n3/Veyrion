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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 显式 HTTP(S)、无 redirect 的 transport，用于有界 provider chat 调用。 */
public final class ProviderChatTransport implements ChatTransport {
    private static final int MAX_KEY_BYTES = 4_096;
    private static final int MAX_ERROR_BODY_BYTES = 8_192;
    private static final int MAX_DIAGNOSTIC_CHARS = 512;
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
                byte[] errorBody = readPrefixBounded(
                        response.body(), Math.min(MAX_ERROR_BODY_BYTES, limits.maxResponseBytes()),
                        limits.requestTimeout());
                try {
                    throw failure("HTTP_" + response.statusCode(),
                            sanitizedDiagnostic(errorBody, headerSecret));
                } finally {
                    Arrays.fill(errorBody, (byte) 0);
                }
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
            return new URI(base.getScheme(), null, base.getHost(), base.getPort(), path, null, null);
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

    private static byte[] readPrefixBounded(InputStream input, int maximum, Duration timeout) {
        AtomicBoolean timedOut = new AtomicBoolean();
        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "provider-chat-error-body-timeout");
            thread.setDaemon(true);
            return thread;
        });
        var timeoutTask = timer.schedule(() -> {
            timedOut.set(true);
            close(input);
        }, timeout.toMillis(), TimeUnit.MILLISECONDS);
        byte[] buffer = new byte[Math.max(1, maximum)];
        int total = 0;
        try (InputStream body = input) {
            while (total < buffer.length) {
                int read = body.read(buffer, total, buffer.length - total);
                if (read == -1) break;
                total += read;
            }
            return Arrays.copyOf(buffer, total);
        } catch (IOException failure) {
            if (timedOut.get()) throw failure("RESPONSE_TIMEOUT");
            return new byte[0];
        } finally {
            Arrays.fill(buffer, (byte) 0);
            timeoutTask.cancel(false);
            timer.shutdownNow();
        }
    }

    private static String sanitizedDiagnostic(byte[] body, String credential) {
        if (body.length == 0) return null;
        String diagnostic;
        try {
            JsonNode root = ChatProtocolSupport.JSON.readTree(body);
            JsonNode error = root == null ? null : root.get("error");
            JsonNode source = error != null && error.isObject() ? error : root;
            if (source == null || !source.isObject()) return null;
            String type = diagnosticField(source, "type");
            String code = diagnosticField(source, "code");
            String message = diagnosticField(source, "message");
            StringBuilder value = new StringBuilder();
            if (type != null) value.append("type=").append(type);
            if (code != null) {
                if (!value.isEmpty()) value.append("; ");
                value.append("code=").append(code);
            }
            if (message != null) {
                if (!value.isEmpty()) value.append("; ");
                value.append("message=").append(message);
            }
            diagnostic = value.toString();
        } catch (Exception malformed) {
            String prefix = new String(body, StandardCharsets.UTF_8);
            String type = diagnosticField(prefix, "type");
            String code = diagnosticField(prefix, "code");
            String message = diagnosticField(prefix, "message");
            StringBuilder value = new StringBuilder();
            if (type != null) value.append("type=").append(type);
            if (code != null) {
                if (!value.isEmpty()) value.append("; ");
                value.append("code=").append(code);
            }
            if (message != null) {
                if (!value.isEmpty()) value.append("; ");
                value.append("message=").append(message);
            }
            diagnostic = value.toString();
        }
        if (diagnostic.isBlank()) return null;
        if (credential != null && credential.length() >= 3) {
            diagnostic = diagnostic.replace(credential, "[REDACTED]");
        }
        diagnostic = diagnostic.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("(?i)(api[_ -]?key\\s*[:=]\\s*)\\S+", "$1[REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]")
                .replaceAll("\\s+", " ").trim();
        return diagnostic.length() <= MAX_DIAGNOSTIC_CHARS
                ? diagnostic : diagnostic.substring(0, MAX_DIAGNOSTIC_CHARS);
    }

    private static String diagnosticField(JsonNode source, String name) {
        JsonNode value = source.get(name);
        if (value == null || !value.isValueNode() || value.isNull()) return null;
        String text = value.asText();
        return text.isBlank() ? null : text;
    }

    private static String diagnosticField(String jsonPrefix, String name) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(name)
                + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\]){0,1024})\"");
        Matcher matcher = pattern.matcher(jsonPrefix);
        if (!matcher.find()) return null;
        String value = matcher.group(1).replace("\\\"", "\"")
                .replace("\\\\", "\\");
        return value.isBlank() ? null : value;
    }

    private static void close(InputStream input) {
        try {
            if (input != null) input.close();
        } catch (IOException ignored) {
            // 已拒绝的 response。
        }
    }

    private static TransportException failure(String code) {
        return new TransportException(code);
    }

    private static TransportException failure(String code, String diagnostic) {
        return new TransportException(code, diagnostic);
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
        private final String diagnostic;
        public TransportException(String code) {
            this(code, null);
        }
        public TransportException(String code, String diagnostic) {
            super(code, null, false, false);
            this.code = code;
            if (diagnostic == null || diagnostic.isBlank()) {
                this.diagnostic = null;
            } else {
                String sanitized = diagnostic.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ")
                        .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                        .replaceAll("(?i)(api[_ -]?key\\s*[:=]\\s*)\\S+", "$1[REDACTED]")
                        .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]")
                        .replaceAll("\\s+", " ").trim();
                this.diagnostic = sanitized.length() <= MAX_DIAGNOSTIC_CHARS
                        ? sanitized : sanitized.substring(0, MAX_DIAGNOSTIC_CHARS);
            }
        }
        public String code() { return code; }
        public String diagnostic() { return diagnostic; }
    }
}
