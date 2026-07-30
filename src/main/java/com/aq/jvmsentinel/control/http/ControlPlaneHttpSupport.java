package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.JsonCodec;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** HTTP 读写、解析、CORS 与请求体辅助。 */
public final class ControlPlaneHttpSupport {
    private ControlPlaneHttpSupport() {}

    public static final class ApiException extends RuntimeException {
        public final int status;
        public final String code;

        public ApiException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }

    public static String safeMessage(Exception exception) {
        String message = exception == null ? null : exception.getMessage();
        return message == null || message.isBlank() ? "invalid request" : message;
    }

    public static Map<String, Object> readObject(HttpExchange exchange) throws IOException {
        String body = readBody(exchange);
        if (body.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return JsonCodec.parseObject(body);
        } catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_JSON", "request body must be a JSON object");
        }
    }

    public static Map<String, Object> readObjectOrEmpty(String body) {
        if (body == null || body.isBlank()) {
            return new LinkedHashMap<>();
        }
        return JsonCodec.parseObject(body);
    }

    public static String readBody(HttpExchange exchange) throws IOException {
        long declared = exchange.getRequestHeaders().getFirst("Content-Length") == null ? -1
                : parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (declared > ControlPlaneHttpLimits.MAX_BODY_BYTES) {
            throw new ApiException(413, "BODY_TOO_LARGE", "request body exceeds the limit");
        }
        try (var input = exchange.getRequestBody()) {
            byte[] bytes = input.readNBytes(ControlPlaneHttpLimits.MAX_BODY_BYTES + 1);
            if (bytes.length > ControlPlaneHttpLimits.MAX_BODY_BYTES) {
                throw new ApiException(413, "BODY_TOO_LARGE", "request body exceeds the limit");
            }
            try {
                var decoder = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
                return decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException invalidEncoding) {
                throw new ApiException(400, "INVALID_ENCODING", "request body must be UTF-8");
            }
        }
    }

    public static long parseContentLength(String value) {
        try {
            long result = Long.parseLong(value);
            if (result < 0) {
                throw new NumberFormatException();
            }
            return result;
        } catch (NumberFormatException invalid) {
            throw new ApiException(400, "INVALID_LENGTH", "invalid Content-Length");
        }
    }

    public static long nonNegativeLong(String value, String name) {
        try {
            long result = Long.parseLong(value);
            if (result < 0) {
                throw new NumberFormatException();
            }
            return result;
        } catch (NumberFormatException invalid) {
            throw new ApiException(400, "INVALID_FIELD", name + " must be a non-negative integer");
        }
    }

    public static List<String> pathSegments(URI uri) {
        String raw = uri.getRawPath();
        if (raw == null || !raw.startsWith(ControlPlaneHttpLimits.API_PREFIX)) {
            throw new ApiException(404, "NOT_FOUND", "route not found");
        }
        if (raw.length() > 4096) {
            throw new ApiException(414, "URI_TOO_LONG", "request path exceeds the limit");
        }
        String remainder = raw.substring(ControlPlaneHttpLimits.API_PREFIX.length());
        if (remainder.isEmpty() || "/".equals(remainder)) {
            return List.of();
        }
        if (!remainder.startsWith("/")) {
            throw new ApiException(404, "NOT_FOUND", "route not found");
        }
        String[] rawSegments = remainder.substring(1).split("/", -1);
        if (rawSegments.length > 8) {
            throw new ApiException(414, "URI_TOO_LONG", "too many path segments");
        }
        List<String> result = new ArrayList<>();
        for (String rawSegment : rawSegments) {
            if (rawSegment.isEmpty()) {
                throw new ApiException(400, "INVALID_PATH", "empty path segment");
            }
            if (rawSegment.length() > 512) {
                throw new ApiException(414, "URI_TOO_LONG", "path segment exceeds the limit");
            }
            try {
                String decoded = URLDecoder.decode(rawSegment.replace("+", "%2B"), StandardCharsets.UTF_8);
                if (decoded.isBlank() || decoded.contains("/") || decoded.contains("\\")
                        || decoded.equals(".") || decoded.equals("..")) {
                    throw new ApiException(400, "INVALID_PATH", "invalid path segment");
                }
                result.add(decoded);
            } catch (ApiException api) {
                throw api;
            } catch (IllegalArgumentException invalid) {
                throw new ApiException(400, "INVALID_PATH", "invalid path encoding");
            }
        }
        return List.copyOf(result);
    }

    public static String query(URI uri, String key) {
        String raw = uri.getRawQuery();
        if (raw == null || raw.isBlank()) {
            return null;
        }
        for (String part : raw.split("&")) {
            int equals = part.indexOf('=');
            String name = equals < 0 ? part : part.substring(0, equals);
            if (!key.equals(decodeQuery(name))) {
                continue;
            }
            return equals < 0 ? "" : decodeQuery(part.substring(equals + 1));
        }
        return null;
    }

    public static String decodeQuery(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_QUERY", "invalid query encoding");
        }
    }

    public static String optionalText(Map<String, Object> body, String key, String fallback) {
        Object value = body.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof String text) || text.isBlank() || text.length() > 4096) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be a non-empty string");
        }
        return text;
    }

    public static String textValue(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("persistent value is missing " + key);
        }
        return text;
    }

    public static String optionalPrompt(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text) || text.length() > 16_384 || text.indexOf('\0') >= 0
                || text.chars().anyMatch(ch -> Character.isISOControl(ch)
                && ch != '\n' && ch != '\r' && ch != '\t')) {
            throw new ApiException(400, "INVALID_FIELD", key + " is invalid");
        }
        return text.isBlank() ? null : text;
    }

    public static String requestIdempotencyKey(HttpExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        if (value == null) {
            return null;
        }
        if (value.isBlank() || value.length() > 256 || value.chars().anyMatch(Character::isWhitespace)) {
            throw new ApiException(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is invalid");
        }
        return value;
    }

    public static String requireIdempotencyKey(HttpExchange exchange) {
        String value = requestIdempotencyKey(exchange);
        if (value == null) {
            throw new ApiException(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required");
        }
        return value;
    }

    public static void ensureIdempotencyCapacity(Map<String, ?> keys, String key) {
        if (key != null && !keys.containsKey(key)
                && keys.size() >= ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS) {
            throw new ApiException(429, "IDEMPOTENCY_LIMIT", "idempotency key store is full");
        }
    }

    public static String idempotencyMapKey(String scope, String key) {
        return scope + "\u0000" + key;
    }

    public static String payloadHash(String payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    public static boolean optionalBoolean(Map<String, Object> body, String key, boolean fallback) {
        Object value = body.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof Boolean bool)) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be boolean");
        }
        return bool;
    }

    public static boolean requiredBoolean(Map<String, Object> body, String key) {
        return optionalBoolean(body, key, false);
    }

    public static long positiveLong(Map<String, Object> body, String key, long fallback) {
        Object value = body.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof Number number) || number.doubleValue() < 1
                || number.doubleValue() > Long.MAX_VALUE
                || number.doubleValue() != Math.rint(number.doubleValue())) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be a positive integer");
        }
        return number.longValue();
    }

    public static List<String> stringList(Object value, String key) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list) || list.size() > ControlPlaneHttpLimits.MAX_LIST_ITEMS) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be an array");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank() || text.length() > 512) {
                throw new ApiException(400, "INVALID_FIELD", key + " contains an invalid value");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    public static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    public static String requireToken(String token) {
        if (token == null || token.isBlank() || token.length() > 512) {
            throw new IllegalArgumentException("mutationToken is required");
        }
        return token;
    }

    public static String newWorkerToken(String mutationToken) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        String token;
        do {
            random.nextBytes(bytes);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } while (constantTimeEquals(mutationToken, token));
        return token;
    }

    public static void addCorsHeaders(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (isLocalOrigin(origin)) {
            // 面向本地 GUI：回显 Origin 以兼容 EventSource credentials。
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
            exchange.getResponseHeaders().set("Vary", "Origin");
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
        }
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers",
                "Content-Type, Content-Length, Authorization, X-Sentinel-Authorization, "
                        + "X-Chunk-SHA256, Last-Event-ID, Idempotency-Key");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    }

    public static boolean isLocalOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return false;
        }
        try {
            URI parsed = URI.create(origin);
            String scheme = parsed.getScheme();
            String host = parsed.getHost();
            return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                    || "[::1]".equalsIgnoreCase(host) || "::1".equals(host));
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    public static void sendJson(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] bytes = JsonCodec.stringify(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Sentinel-Schema-Version", Integer.toString(ApiDtos.SCHEMA_VERSION));
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    public static void sendEmpty(HttpExchange exchange, int status) throws IOException {
        exchange.sendResponseHeaders(status, -1);
    }

    public static void sendError(HttpExchange exchange, int status, String code,
                                 String message, String requestId) throws IOException {
        try {
            sendJson(exchange, status, Map.of(
                    "schemaVersion", ApiDtos.SCHEMA_VERSION,
                    "code", code,
                    "message", message == null ? "request failed" : message,
                    "requestId", requestId));
        } catch (IOException ignored) {
            // 客户端可能已断开。
        }
    }

    public static boolean isSseRequest(HttpExchange exchange) {
        String accept = exchange.getRequestHeaders().getFirst("Accept");
        return accept != null && accept.toLowerCase(Locale.ROOT).contains("text/event-stream");
    }
}
