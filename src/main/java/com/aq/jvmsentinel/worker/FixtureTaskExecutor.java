package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.OpenSandboxClient;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Executes one catalog-owned fixture task through OpenSandbox. It never launches a host process.
 */
public final class FixtureTaskExecutor {
    static final String TRACE_DIRECTORY = "/sandbox/trace";
    static final String TRACE_FILE = TRACE_DIRECTORY + "/agent-events.jsonl";
    static final String AGENT_PATH = "/opt/veyrion/agent/veyrion-agent.jar";
    static final String FIXTURE_CLASSPATH = "/opt/veyrion/fixture/fixture.jar";
    private static final int SANDBOX_UID = 10000;
    private static final int SANDBOX_GID = 10000;
    private static final long MAX_INGEST_BYTES = 1024L * 1024;

    private final WorkerControlPlaneClient control;
    private final OpenSandboxClient sandbox;
    private final AgentJsonlTraceConverter converter;
    private final String workerId;

    public FixtureTaskExecutor(WorkerControlPlaneClient control, OpenSandboxClient sandbox,
                               AgentJsonlTraceConverter converter, String workerId) {
        this.control = Objects.requireNonNull(control, "control");
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.converter = Objects.requireNonNull(converter, "converter");
        this.workerId = requireId(workerId, "workerId");
    }

    /** Executes exactly one task using only the authenticated internal task specification. */
    public ExecutionResult execute(ExecutionRequest request) {
        Objects.requireNonNull(request, "request");
        WorkerControlPlaneClient.TaskDescriptor descriptor = control.get(request.scope());
        WorkerTaskSpec spec = materializeSpec(descriptor);
        validateExecutable(spec);

        WorkerLease lease = null;
        String sandboxId = null;
        RuntimeException primary = null;
        try {
            lease = control.lease(spec.scope(), workerId, Set.of(WorkerCapability.FIXTURE_RUNC),
                    Duration.ofSeconds(Math.max(60, Math.min(86_400, spec.resourceBudget().maxWallClockSeconds() + 30))));
            requireLease(lease, spec.scope());
            WorkerControlPlaneClient.TaskDescriptor started =
                    control.start(spec.scope(), lease.leaseId(), workerId);
            requireDescriptor(started, spec, TaskLifecycle.RUNNING);

            SandboxHandle handle = sandbox.create(new SandboxRequest(
                    spec.imageUri(), List.of("/bin/sleep", "infinity"), timeoutSeconds(spec.resourceBudget()),
                    spec.resourceBudget(), true, WorkerCapability.FIXTURE_RUNC));
            sandboxId = handle.id();

            CommandResult run = sandbox.command(sandboxId, new CommandRequest(
                    fixtureCommand(spec), "/sandbox", commandTimeout(spec.resourceBudget()),
                    SANDBOX_UID, SANDBOX_GID));
            if (run.exitCode() != 0) {
                throw new FixtureExecutionException("FIXTURE_EXIT_NONZERO",
                        "fixture command returned a non-zero exit code", null);
            }

            CommandResult traceRead = sandbox.command(sandboxId, new CommandRequest(
                    "/bin/cat " + TRACE_FILE, "/sandbox", Duration.ofSeconds(10),
                    SANDBOX_UID, SANDBOX_GID));
            if (traceRead.exitCode() != 0) {
                throw new FixtureExecutionException("TRACE_READ_FAILED",
                        "fixture trace could not be read", null);
            }
            byte[] jsonl = traceRead.stdout().getBytes(StandardCharsets.UTF_8);
            long ingestionLimit = Math.min(MAX_INGEST_BYTES, spec.resourceBudget().maxTraceBytes());
            if (jsonl.length > ingestionLimit) {
                throw new FixtureExecutionException("TRACE_TOO_LARGE",
                        "fixture trace exceeds the Worker ingestion limit", null);
            }

            List<TraceChunk> chunks = converter.convert(jsonl, spec.scope(), spec.resourceBudget());
            for (TraceChunk chunk : chunks) {
                control.commitTrace(spec.scope(), lease.leaseId(), workerId, chunk);
            }
            sandbox.delete(sandboxId);
            sandboxId = null;
            WorkerControlPlaneClient.TaskDescriptor completed =
                    control.complete(spec.scope(), lease.leaseId(), workerId);
            requireDescriptor(completed, spec, TaskLifecycle.COMPLETED);
            return new ExecutionResult(spec.scope(), chunks.size(),
                    chunks.get(chunks.size() - 1).digest(), TaskLifecycle.COMPLETED);
        } catch (RuntimeException failure) {
            primary = failure;
            if (lease != null) {
                try {
                    control.fail(spec.scope(), lease.leaseId(), workerId,
                            StopReason.WORKER_FAILURE, failureCode(failure));
                } catch (RuntimeException failFailure) {
                    failure.addSuppressed(failFailure);
                }
            }
            throw failure;
        } finally {
            if (sandboxId != null) {
                try {
                    sandbox.delete(sandboxId);
                } catch (RuntimeException cleanupFailure) {
                    if (primary != null) {
                        primary.addSuppressed(cleanupFailure);
                    } else {
                        throw cleanupFailure;
                    }
                }
            }
        }
    }

    private static WorkerTaskSpec materializeSpec(WorkerControlPlaneClient.TaskDescriptor value) {
        return new WorkerTaskSpec(1, value.scope().projectId(), value.scope().artifactDigest(),
                value.scope().scanId(), value.scope().taskId(), value.targetEntryId(),
                value.authorized(), value.fixtureOnly(), value.resourceBudget(), value.networkPolicy(),
                value.requiredCapability(), value.fixtureId(), value.imageUri(),
                value.mainClass(), value.fixtureDigest());
    }

    private static void validateExecutable(WorkerTaskSpec spec) {
        if (!spec.authorized()) throw new SecurityException("fixture task is not authorized");
        if (!spec.fixtureOnly()) throw new SecurityException("only fixture tasks may use FIXTURE_RUNC");
        if (spec.requiredCapability() != WorkerCapability.FIXTURE_RUNC) {
            throw new SecurityException("fixture executor requires FIXTURE_RUNC");
        }
        if (spec.networkPolicy().mode() != NetworkMode.DENY
                || !spec.networkPolicy().allowlist().isEmpty()) {
            throw new SecurityException("fixture executor requires deny-all network policy");
        }
        if (spec.fixtureId() == null || spec.imageUri() == null
                || spec.mainClass() == null || spec.fixtureDigest() == null) {
            throw new SecurityException("fixture runtime fields are incomplete");
        }
        // Re-check independently at the execution boundary.
        if (!spec.imageUri().matches("[a-z0-9.-]+(?:/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}")
                || !spec.imageUri().endsWith("@sha256:" + spec.fixtureDigest())) {
            throw new SecurityException("fixture image is not digest-pinned");
        }
        if (!spec.mainClass().matches("[A-Za-z_$][A-Za-z0-9_$.]{0,254}")) {
            throw new SecurityException("fixture main class is invalid");
        }
        if (spec.resourceBudget().maxTraceBytes() < 256) {
            throw new SecurityException("trace budget is too small for the Agent");
        }
    }

    private void requireLease(WorkerLease lease, TaskScope scope) {
        if (!lease.scope().equals(scope) || !lease.workerId().equals(workerId)
                || lease.capability() != WorkerCapability.FIXTURE_RUNC) {
            throw new SecurityException("lease binding does not match the execution");
        }
    }

    private static void requireDescriptor(WorkerControlPlaneClient.TaskDescriptor value,
                                          WorkerTaskSpec spec, TaskLifecycle lifecycle) {
        if (!value.scope().equals(spec.scope()) || value.lifecycle() != lifecycle
                || !Objects.equals(value.fixtureId(), spec.fixtureId())
                || !Objects.equals(value.imageUri(), spec.imageUri())
                || !Objects.equals(value.mainClass(), spec.mainClass())
                || !Objects.equals(value.fixtureDigest(), spec.fixtureDigest())) {
            throw new SecurityException("task response changed execution identity");
        }
    }

    private static String fixtureCommand(WorkerTaskSpec spec) {
        long maxBytes = Math.min(64L * 1024 * 1024, spec.resourceBudget().maxTraceBytes());
        return "java"
                + " -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -Dveyrion.sandbox.traceDir.authorized=true"
                + " -javaagent:" + AGENT_PATH + "=maxBytes=" + maxBytes
                + " -cp " + FIXTURE_CLASSPATH
                + " '" + spec.mainClass() + "'";
    }

    private static int timeoutSeconds(ResourceBudget budget) {
        if (budget.maxWallClockSeconds() < 60 || budget.maxWallClockSeconds() > 86_400) {
            throw new SecurityException("sandbox wall-clock budget is outside OpenSandbox limits");
        }
        return Math.toIntExact(budget.maxWallClockSeconds());
    }

    private static Duration commandTimeout(ResourceBudget budget) {
        return Duration.ofSeconds(Math.min(3_600, budget.maxWallClockSeconds()));
    }

    private static String failureCode(RuntimeException failure) {
        if (failure instanceof FixtureExecutionException fixture) return fixture.code();
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return "FIXTURE_INPUT_REJECTED";
        }
        return "FIXTURE_EXECUTION_FAILED";
    }

    private static String requireId(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    public record ExecutionResult(TaskScope scope, int traceChunks, String traceHeadDigest,
                                  TaskLifecycle lifecycle) {
        public ExecutionResult {
            Objects.requireNonNull(scope, "scope");
            if (traceChunks <= 0) throw new IllegalArgumentException("traceChunks must be positive");
            Objects.requireNonNull(traceHeadDigest, "traceHeadDigest");
            if (lifecycle != TaskLifecycle.COMPLETED) {
                throw new IllegalArgumentException("execution result must be completed");
            }
        }
    }

    public record ExecutionRequest(TaskScope scope) {
        public ExecutionRequest {
            Objects.requireNonNull(scope, "scope");
        }
    }

    public static final class FixtureExecutionException extends RuntimeException {
        private final String code;

        private FixtureExecutionException(String code, String message, Throwable cause) {
            super(message, cause);
            this.code = requireId(code, "code");
        }

        public String code() { return code; }
    }
}
