package com.aq.jvmsentinel.worker.session;

import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.worker.TaskScope;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 断网沙箱会话保留：供 PATH/TRIAGE 复用已启动的应用容器。
 */
public final class RetainedSandboxSessions {
    private static final int MAX_RETAINED_SESSIONS = 8;
    private final Duration ttl;
    private final Map<SessionKey, RetainedSandboxSession> sessions = new ConcurrentHashMap<>();

    public RetainedSandboxSessions(Duration ttl) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
    }

    public RetainedSandboxSession get(TaskScope scope, String sha256) {
        SessionKey key = SessionKey.from(scope);
        RetainedSandboxSession session = sessions.get(key);
        if (session == null || !session.sha256().equals(sha256)
                || session.expiresAtNanos() < System.nanoTime()) {
            return null;
        }
        return session;
    }

    public void retain(TaskScope scope, String sha256, String sandboxId, int httpPort,
                       SandboxRuntimeClient sandbox) {
        SessionKey key = SessionKey.from(scope);
        RetainedSandboxSession prior = sessions.put(key,
                new RetainedSandboxSession(key, sha256, sandboxId, httpPort, deadlineNanos()));
        if (prior != null && !prior.sandboxId().equals(sandboxId)) {
            deleteQuietly(sandbox, prior.sandboxId());
        }
        if (sessions.size() > MAX_RETAINED_SESSIONS) {
            RetainedSandboxSession oldest = sessions.values().stream()
                    .min(java.util.Comparator.comparingLong(RetainedSandboxSession::expiresAtNanos))
                    .orElse(null);
            if (oldest != null && sessions.remove(oldest.key(), oldest)
                    && !oldest.sandboxId().equals(sandboxId)) {
                deleteQuietly(sandbox, oldest.sandboxId());
            }
        }
    }

    public void touch(RetainedSandboxSession session) {
        if (session == null) return;
        sessions.computeIfPresent(session.key(), (ignored, existing) ->
                existing.sandboxId().equals(session.sandboxId())
                        ? new RetainedSandboxSession(existing.key(), existing.sha256(),
                        existing.sandboxId(), existing.httpPort(), deadlineNanos())
                        : existing);
    }

    public void release(RetainedSandboxSession session, SandboxRuntimeClient sandbox) {
        if (session == null) return;
        if (sessions.remove(session.key(), session)) {
            deleteQuietly(sandbox, session.sandboxId());
        }
    }

    public void releaseExpired(SandboxRuntimeClient sandbox) {
        long now = System.nanoTime();
        for (RetainedSandboxSession session : List.copyOf(sessions.values())) {
            if (session.expiresAtNanos() < now && sessions.remove(session.key(), session)) {
                deleteQuietly(sandbox, session.sandboxId());
            }
        }
    }

    public void releaseAll(SandboxRuntimeClient sandbox) {
        for (RetainedSandboxSession session : List.copyOf(sessions.values())) {
            if (sessions.remove(session.key(), session)) {
                deleteQuietly(sandbox, session.sandboxId());
            }
        }
    }

    public void releaseForScan(String projectId, String artifactDigest, String scanId,
                               SandboxRuntimeClient sandbox) {
        SessionKey key = new SessionKey(projectId, artifactDigest, scanId);
        RetainedSandboxSession session = sessions.remove(key);
        if (session != null) {
            deleteQuietly(sandbox, session.sandboxId());
        }
    }

    private static void deleteQuietly(SandboxRuntimeClient sandbox, String sandboxId) {
        try {
            sandbox.delete(sandboxId);
        } catch (RuntimeException ignored) {
            // 尽力清理；沙箱后端也可能在进程退出时自行清理。
        }
    }

    private long deadlineNanos() {
        long now = System.nanoTime();
        long ttlNanos = ttl.toNanos();
        if (ttlNanos <= 0 || Long.MAX_VALUE - now < ttlNanos) return Long.MAX_VALUE;
        return now + ttlNanos;
    }

    public record SessionKey(String projectId, String artifactDigest, String scanId) {
        static SessionKey from(TaskScope scope) {
            return new SessionKey(scope.projectId(), scope.artifactDigest(), scope.scanId());
        }
    }

    public record RetainedSandboxSession(SessionKey key, String sha256, String sandboxId,
                                         int httpPort, long expiresAtNanos) { }
}
