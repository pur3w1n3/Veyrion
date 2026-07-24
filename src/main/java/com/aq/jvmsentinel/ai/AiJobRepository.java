package com.aq.jvmsentinel.ai;

import java.util.List;
import java.util.Optional;

/** Workspace-scoped persistence boundary for AI data-flow state. */
public interface AiJobRepository {
    void save(AiContracts.AiJob job);
    Optional<AiContracts.AiJob> find(String workspaceId, String jobId);
    List<AiContracts.AiJob> list(String workspaceId);
}
