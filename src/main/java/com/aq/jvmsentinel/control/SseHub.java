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
 * Bounded Server-Sent Events hub.  Events are retained per scan for a short
 * replay window; clients must reconcile state with the idempotent GET APIs
 * after a gap or a reconnect.
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
                    // A slow client receives the latest state eventually.  It
                    // must use GET reconciliation; retaining an unbounded
                    // queue would turn an SSE connection into a memory sink.
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
     * Handles one SSE request.  This method intentionally blocks until the
     * browser closes the connection; the HTTP server must use a worker pool.
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
                    // If the caller acknowledged the terminal event exactly,
                    // there is nothing left to stream.  Do not hold an idle
                    // connection open forever.
                    terminal = historyContainsTerminalAfter(channel, lastEventId);
                }
                output.flush();
                // A completed scan has a finite event log.  Closing after the
                // terminal event makes one-shot HTTP clients deterministic and
                // prevents browsers from reconnecting forever to an already
                // completed scan.  An in-flight scan remains a live stream.
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
            // Browser disconnects are normal for SSE.  GET reconciliation is
            // the source of truth if the stream ended during a write.
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
        // If the requested ID has fallen out of the bounded history, replay
        // what is available.  The client then performs a GET reconciliation.
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
            // Keep both the nested context and flat identifiers.  The nested
            // form is the canonical contract; flat fields make lightweight
            // EventSource consumers and log shippers backwards compatible.
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
            // A null marker cannot be stored in ArrayBlockingQueue.  Dropping
            // the oldest event is sufficient: the next reconnect/GET fills
            // any gap, and the queue remains bounded.
            queue.poll();
        }
    }
}
