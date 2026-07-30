package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.event.VersionedEvent;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * 有界 Server-Sent Events 中心。事件按 scan 保留短 replay 窗口；
 * 客户端在 gap 或重连后必须用幂等 GET API 对账状态。
 */
public final class SseHub {
    private static final int HISTORY_LIMIT = 256;
    private static final int CLIENT_QUEUE_LIMIT = 128;
    private static final int MAX_CLIENTS_PER_SCAN = 64;
    private static final long HEARTBEAT_SECONDS = 15;

    private final Map<String, Channel> channels = new ConcurrentHashMap<>();
    private volatile EventPersistence persistence = EventPersistence.NONE;

    public synchronized void attachPersistence(Collection<VersionedEvent> events, EventPersistence persistence) {
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        if (events == null) return;
        for (VersionedEvent event : events) {
            String scanId = event.context() == null ? null : event.context().scanId();
            if (scanId == null) continue;
            Channel channel = channels.computeIfAbsent(scanId, ignored -> new Channel());
            synchronized (channel) {
                channel.history.addLast(event);
                while (channel.history.size() > HISTORY_LIMIT) channel.history.removeFirst();
            }
        }
    }

    public void publish(String scanId, VersionedEvent event) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(event, "event");
        persistence.save(scanId, event);
        Channel channel = channels.computeIfAbsent(scanId, ignored -> new Channel());
        synchronized (channel) {
            channel.history.addLast(event);
            while (channel.history.size() > HISTORY_LIMIT) channel.history.removeFirst();
            for (Client client : List.copyOf(channel.clients)) {
                if (!client.offer(event)) {
                    // 慢客户端最终会收到最新状态；须用 GET 对账。
                    // 无界队列会把 SSE 连接变成内存 sink。
                    client.offerGapMarker();
                }
            }
        }
    }

    public List<VersionedEvent> history(String scanId) {
        Channel channel = channels.get(scanId);
        if (channel == null) return List.of();
        synchronized (channel) { return List.copyOf(channel.history); }
    }

    /**
     * 处理一次 SSE 请求。本方法有意阻塞直到 browser 关闭连接；
     * HTTP server 须使用 worker pool。
     */
    public void open(HttpExchange exchange, String scanId, String lastEventId) throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Channel channel = channels.computeIfAbsent(scanId, ignored -> new Channel());
        Client client = new Client();
        List<VersionedEvent> replay;
        synchronized (channel) {
            if (channel.clients.size() >= MAX_CLIENTS_PER_SCAN) {
                exchange.sendResponseHeaders(429, -1);
                exchange.close();
                return;
            }
            replay = replay(channel.history, lastEventId);
            channel.clients.add(client);
        }
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/event-stream; charset=utf-8");
        headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.set("Connection", "keep-alive");
        headers.set("X-Accel-Buffering", "no");
        headers.set("X-Sentinel-Schema-Version", Integer.toString(ApiDtos.EVENT_SCHEMA_VERSION));
        try {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream output = exchange.getResponseBody()) {
                writeFrame(output, "retry: 3000\n\n");
                boolean terminal = false;
                for (VersionedEvent event : replay) {
                    writeEvent(output, event);
                    terminal |= isTerminal(event);
                }
                if (!terminal && lastEventId != null && !lastEventId.isBlank()) {
                    // 调用方已精确确认终态事件时，无需再 stream。
                    // 勿永久保持空闲连接。
                    terminal = historyContainsTerminalAfter(channel, lastEventId);
                }
                output.flush();
                // 已完成 scan 的事件日志有限。终态事件后关闭使一次性 HTTP client 行为确定，
                // 并防止 browser 对已完成的 scan 无限重连。在途 scan 仍为 live stream。
                while (!client.closed && !terminal) {
                    VersionedEvent event = client.queue.poll(HEARTBEAT_SECONDS, TimeUnit.SECONDS);
                    if (event == null) {
                        writeFrame(output, ": heartbeat\n\n");
                    } else {
                        writeEvent(output, event);
                        terminal = isTerminal(event);
                    }
                    output.flush();
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (IOException ignored) {
            // browser 断开对 SSE 属正常。stream 在写入中结束时以 GET 对账为准。
        } finally {
            client.closed = true;
            synchronized (channel) { channel.clients.remove(client); }
            try { exchange.close(); } catch (RuntimeException ignored) { }
        }
    }

    public void close() {
        for (Channel channel : channels.values()) {
            synchronized (channel) {
                for (Client client : channel.clients) client.closed = true;
                channel.clients.clear();
            }
        }
        channels.clear();
    }

    private static List<VersionedEvent> replay(Deque<VersionedEvent> history, String lastEventId) {
        List<VersionedEvent> result = new ArrayList<>();
        boolean found = lastEventId == null || lastEventId.isBlank();
        for (VersionedEvent event : history) {
            if (!found) {
                if (event.eventId().equals(lastEventId)) found = true;
                continue;
            }
            result.add(event);
        }
        // 请求的 ID 已超出有界 history 时，replay 可用部分；client 再执行 GET 对账。
        if (!found) result = new ArrayList<>(history);
        return List.copyOf(result);
    }

    private static boolean isTerminal(VersionedEvent event) {
        return "ScanCompleted".equals(event.eventType()) || "TaskStopped".equals(event.eventType());
    }

    private static boolean historyContainsTerminalAfter(Channel channel, String lastEventId) {
        synchronized (channel) {
            boolean seen = false;
            for (VersionedEvent event : channel.history) {
                if (seen && isTerminal(event)) return true;
                if (event.eventId().equals(lastEventId)) {
                    seen = true;
                    if (isTerminal(event)) return true;
                }
            }
            return false;
        }
    }

    private static void writeEvent(OutputStream output, VersionedEvent event) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("eventId", event.eventId());
        body.put("eventType", event.eventType());
        body.put("schemaVersion", event.schemaVersion());
        body.put("occurredAt", event.occurredAt().toString());
        body.put("payloadRef", "memory://events/" + event.eventId());
        if (event.context() != null) {
            // 同时保留嵌套 context 与扁平标识符。嵌套形式为规范 contract；
            // 扁平字段便于轻量 EventSource 消费者与 log shipper 向后兼容。
            body.put("projectId", event.context().projectId());
            body.put("artifactDigest", event.context().artifactDigest());
            body.put("scanId", event.context().scanId());
            body.put("taskId", event.context().taskId());
            Map<String, Object> context = new LinkedHashMap<>();
            context.put("projectId", event.context().projectId());
            context.put("artifactDigest", event.context().artifactDigest());
            context.put("scanId", event.context().scanId());
            context.put("taskId", event.context().taskId());
            body.put("context", context);
        }
        Map<String, Object> key = new LinkedHashMap<>();
        key.put("scope", event.idempotencyKey().scope());
        key.put("value", event.idempotencyKey().value());
        body.put("idempotencyKey", event.idempotencyKey().scope() + ":" + event.idempotencyKey().value());
        body.put("idempotency", key);
        try {
            Object parsedPayload = JsonCodec.parse(event.payload());
            body.put("payload", parsedPayload);
            if (parsedPayload instanceof Map<?, ?> payloadMap) {
                promote(payloadMap, body, "verificationStatus");
                promote(payloadMap, body, "dependencyMode");
                promote(payloadMap, body, "evidenceRefs");
                promote(payloadMap, body, "status");
            }
        } catch (IllegalArgumentException invalidPayload) {
            body.put("payload", Map.of("raw", event.payload()));
        }
        String frame = "id: " + event.eventId() + "\n"
                + "event: " + event.eventType() + "\n"
                + "data: " + JsonCodec.stringify(body) + "\n\n";
        writeFrame(output, frame);
    }

    private static void writeFrame(OutputStream output, String frame) throws IOException {
        output.write(frame.getBytes(StandardCharsets.UTF_8));
    }

    private static void promote(Map<?, ?> payload, Map<String, Object> body, String key) {
        if (payload.containsKey(key)) body.put(key, payload.get(key));
    }

    private static final class Channel {
        private final Deque<VersionedEvent> history = new ArrayDeque<>();
        private final List<Client> clients = new ArrayList<>();
    }

    public interface EventPersistence {
        EventPersistence NONE = (scanId, event) -> { };
        void save(String scanId, VersionedEvent event);
    }

    private static final class Client {
        private final ArrayBlockingQueue<VersionedEvent> queue = new ArrayBlockingQueue<>(CLIENT_QUEUE_LIMIT);
        private volatile boolean closed;

        private boolean offer(VersionedEvent event) {
            if (closed) return true;
            if (queue.offer(event)) return true;
            queue.poll();
            return queue.offer(event);
        }

        private void offerGapMarker() {
            // null 标记无法存入 ArrayBlockingQueue。丢弃最旧事件即可：
            // 下次重连/GET 会补齐 gap，队列保持有界。
            queue.poll();
        }
    }
}
