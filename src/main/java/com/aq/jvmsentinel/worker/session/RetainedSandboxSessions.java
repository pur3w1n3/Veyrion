package com.aq.jvmsentinel.worker.session;

import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.worker.LocalWorkerQuota;
import com.aq.jvmsentinel.worker.TaskScope;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 断网沙箱会话保留：供 PATH/TRIAGE 复用已启动的应用容器。
 *
 * <p>驱逐优先同 project 内 LRU；禁止为 A 的新会话直接踢 B 的保留会话。
 * 全局硬顶且无法同 project 腾挪时拒绝保留（返回 false，由调用方删除新容器）。</p>
 */
public final class RetainedSandboxSessions {
    private final Duration ttl;
    private final LocalWorkerQuota quota;
    private final Map<SessionKey, RetainedSandboxSession> sessions = new ConcurrentHashMap<>();

    public RetainedSandboxSessions(Duration ttl) {
        this(ttl, LocalWorkerQuota.defaults());
    }

    public RetainedSandboxSessions(Duration ttl, LocalWorkerQuota quota) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.quota = Objects.requireNonNull(quota, "quota");
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

    /**
     * 尝试保留沙箱会话。
     *
     * @return {@code true} 已保留；{@code false} 因全局硬顶无法同 project 腾挪而拒绝
     *         （调用方须删除 {@code sandboxId}；不会跨 project 驱逐）
     */
    public boolean retain(TaskScope scope, String sha256, String sandboxId, int httpPort,
                          SandboxRuntimeClient sandbox) {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(sandboxId, "sandboxId");
        Objects.requireNonNull(sandbox, "sandbox");

        SessionKey key = SessionKey.from(scope);
        RetainedSandboxSession prior = sessions.put(key,
                new RetainedSandboxSession(key, sha256, sandboxId, httpPort, deadlineNanos()));
        if (prior != null && !prior.sandboxId().equals(sandboxId)) {
            deleteQuietly(sandbox, prior.sandboxId());
        }

        evictSameProjectOverflow(scope.projectId(), key, sandbox);

        if (sessions.size() <= quota.maxGlobalRetainedSessions()) {
            return true;
        }

        // 全局硬顶：只允许同 project 腾挪；禁止踢其他 project。
        while (sessions.size() > quota.maxGlobalRetainedSessions()) {
            RetainedSandboxSession victim = oldestInProject(scope.projectId(), key);
            if (victim == null) {
                RetainedSandboxSession rejected = sessions.get(key);
                if (rejected != null && rejected.sandboxId().equals(sandboxId)
                        && sessions.remove(key, rejected)) {
                    // 调用方负责 delete；此处不删，避免双删。
                    return false;
                }
                return sessions.containsKey(key);
            }
            if (sessions.remove(victim.key(), victim)) {
                deleteQuietly(sandbox, victim.sandboxId());
            }
        }
        return true;
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

    /** 测试与诊断：当前保留会话数。 */
    public int size() {
        return sessions.size();
    }

    /** 测试与诊断：某 project 的保留会话数。 */
    public int sizeForProject(String projectId) {
        Objects.requireNonNull(projectId, "projectId");
        int count = 0;
        for (RetainedSandboxSession session : sessions.values()) {
            if (projectId.equals(session.key().projectId())) {
                count++;
            }
        }
        return count;
    }

    public boolean contains(String projectId, String artifactDigest, String scanId) {
        return sessions.containsKey(new SessionKey(projectId, artifactDigest, scanId));
    }

    private void evictSameProjectOverflow(String projectId, SessionKey keep, SandboxRuntimeClient sandbox) {
        while (sizeForProject(projectId) > quota.maxPerProjectRetainedSessions()) {
            RetainedSandboxSession victim = oldestInProject(projectId, keep);
            if (victim == null) {
                break;
            }
            if (sessions.remove(victim.key(), victim)) {
                deleteQuietly(sandbox, victim.sandboxId());
            }
        }
    }

    private RetainedSandboxSession oldestInProject(String projectId, SessionKey exclude) {
        RetainedSandboxSession oldest = null;
        for (RetainedSandboxSession session : sessions.values()) {
            if (!projectId.equals(session.key().projectId())) {
                continue;
            }
            if (exclude != null && exclude.equals(session.key())) {
                continue;
            }
            if (oldest == null || session.expiresAtNanos() < oldest.expiresAtNanos()) {
                oldest = session;
            }
        }
        return oldest;
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
