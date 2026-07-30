package com.aq.jvmsentinel.sandbox;

import java.nio.file.Path;

/**
 * 授权 artifact executor 消费的最小 lifecycle 面。
 *
 * <p>实现仍为 deployment-owned。runtime 实现不能自行授予
 * permission 或选择强于 task 要求的 capability。</p>
 */
public interface SandboxRuntimeClient extends AutoCloseable {
    SandboxHandle create(SandboxRequest request);

    CommandResult command(String sandboxId, CommandRequest request);

    /**
     * 将 host file 复制进 sandbox。用于不能内联进
     * {@code docker exec} 的大 probe plan（Windows CreateProcess 命令行限制）。
     */
    default void uploadFile(String sandboxId, Path hostFile, String containerPath) {
        throw new UnsupportedOperationException("uploadFile is not supported by this sandbox client");
    }

    void delete(String sandboxId);

    @Override
    default void close() { }
}
