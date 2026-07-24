package com.aq.jvmsentinel.sandbox;

/**
 * Minimal lifecycle surface consumed by authorized artifact executors.
 *
 * <p>Implementations remain deployment-owned. A runtime implementation cannot grant itself
 * permission or select a stronger capability than the task requires.</p>
 */
public interface SandboxRuntimeClient extends AutoCloseable {
    SandboxHandle create(SandboxRequest request);

    CommandResult command(String sandboxId, CommandRequest request);

    void delete(String sandboxId);

    @Override
    default void close() { }
}
