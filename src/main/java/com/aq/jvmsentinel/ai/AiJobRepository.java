package com.aq.jvmsentinel.ai;

import java.util.List;
import java.util.Optional;

/** AI 数据流状态的 workspace 作用域持久化边界。 */
public interface AiJobRepository {
    void save(AiContracts.AiJob job);
    Optional<AiContracts.AiJob> find(String workspaceId, String jobId);
    List<AiContracts.AiJob> list(String workspaceId);
}
