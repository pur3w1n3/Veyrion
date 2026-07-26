package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.provider.AgentRole;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Server-bound scope and budget. No value in this object is read from a model
 * ToolCall, and role allowlists cannot be supplied or extended by callers.
 */
public final class ToolExecutionContext {
    private static final Map<AgentRole, Set<String>> ROLE_TOOLS = Map.of(
            AgentRole.PRE_ANALYSIS, Set.of("facts_search", "evidence_get"),
            AgentRole.DYNAMIC_VERIFICATION, Set.of("facts_search", "evidence_get", "plan_propose", "sandbox_probe"),
            AgentRole.PATH_EXPLORATION, Set.of("facts_search", "evidence_get", "plan_propose"),
            AgentRole.VULNERABILITY_TRIAGE, Set.of("facts_search", "evidence_get", "plan_propose", "sandbox_probe"),
            AgentRole.REPORT_GENERATION, Set.of("facts_search", "evidence_get", "plan_propose"));

    private final Scope scope;
    private final String principalId;
    private final String jobId;
    private final AgentRole role;
    private final Set<String> allowedTools;
    private final Budget budget;
    private final Clock clock;
    private final AtomicInteger calls = new AtomicInteger();
    private final AtomicBoolean cancelled = new AtomicBoolean();

    private ToolExecutionContext(Scope scope, String principalId, String jobId, AgentRole role,
                                 Budget budget, Clock clock) {
        this.scope = Objects.requireNonNull(scope, "scope");
        this.principalId = id(principalId, "principalId");
        this.jobId = id(jobId, "jobId");
        this.role = Objects.requireNonNull(role, "role");
        this.allowedTools = ROLE_TOOLS.get(role);
        this.budget = Objects.requireNonNull(budget, "budget");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static ToolExecutionContext bind(Scope scope, String principalId, String jobId,
                                            AgentRole role, Budget budget) {
        return new ToolExecutionContext(scope, principalId, jobId, role, budget, Clock.systemUTC());
    }

    static ToolExecutionContext bind(Scope scope, String principalId, String jobId,
                                     AgentRole role, Budget budget, Clock clock) {
        return new ToolExecutionContext(scope, principalId, jobId, role, budget, clock);
    }

    public Scope scope() { return scope; }
    public String principalId() { return principalId; }
    public String jobId() { return jobId; }
    public AgentRole role() { return role; }
    public Set<String> allowedTools() { return allowedTools; }
    public Budget budget() { return budget; }
    public boolean isCancelled() { return cancelled.get(); }
    public void cancel() { cancelled.set(true); }

    boolean expired() { return !clock.instant().isBefore(budget.deadline()); }
    boolean consumeCall() {
        int value = calls.incrementAndGet();
        return value <= budget.maxCalls();
    }

    public record Scope(String workspaceId, String projectId) {
        public Scope {
            workspaceId = id(workspaceId, "workspaceId");
            projectId = id(projectId, "projectId");
        }
    }

    public record Budget(int maxCalls, int maxArgumentBytes, int maxJsonDepth,
                         int maxResultBytes, Instant deadline) {
        public Budget {
            if (maxCalls < 1 || maxCalls > 10_000) throw new IllegalArgumentException("maxCalls is invalid");
            if (maxArgumentBytes < 2 || maxArgumentBytes > 1024 * 1024) {
                throw new IllegalArgumentException("maxArgumentBytes is invalid");
            }
            if (maxJsonDepth < 1 || maxJsonDepth > 64) throw new IllegalArgumentException("maxJsonDepth is invalid");
            if (maxResultBytes < 64 || maxResultBytes > 16 * 1024 * 1024) {
                throw new IllegalArgumentException("maxResultBytes is invalid");
            }
            Objects.requireNonNull(deadline, "deadline");
        }
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > 512
                || value.chars().anyMatch(c -> c == 0 || c == '\r' || c == '\n')) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }
}
