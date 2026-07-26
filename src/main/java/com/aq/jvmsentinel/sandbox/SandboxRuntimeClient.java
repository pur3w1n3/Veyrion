package com.aq.jvmsentinel.sandbox;

import java.nio.file.Path;

/**
 * Minimal lifecycle surface consumed by authorized artifact executors.
 *
 * <p>Implementations remain deployment-owned. A runtime implementation cannot grant itself
 * permission or select a stronger capability than the task requires.</p>
 */
public interface SandboxRuntimeClient extends AutoCloseable {
    SandboxHandle create(SandboxRequest request);

    CommandResult command(String sandboxId, CommandRequest request);

    /**
     * Copies a host file into the sandbox. Used for large probe plans that must not be inlined
     * into {@code docker exec} (Windows CreateProcess command-line limit).
     */
    default void uploadFile(String sandboxId, Path hostFile, String containerPath) {
        throw new UnsupportedOperationException("uploadFile is not supported by this sandbox client");
    }

    void delete(String sandboxId);

    @Override
    default void close() { }
}
