package com.aq.jvmsentinel.provider;

import java.util.List;
import java.util.Optional;

/**
 * Workspace-scoped provider/model configuration persistence.
 * Credential material is intentionally absent; use ProviderCredentialRepository separately.
 */
public interface ProviderRepository {
    void saveProvider(ProviderContracts.ProviderDefinition provider);
    Optional<ProviderContracts.ProviderDefinition> findProvider(String workspaceId, String providerId);
    List<ProviderContracts.ProviderDefinition> listProviders(String workspaceId);

    void saveModel(ProviderContracts.ModelDefinition model);
    Optional<ProviderContracts.ModelDefinition> findModel(String workspaceId, String modelId);
    List<ProviderContracts.ModelDefinition> listModels(String workspaceId, String providerId);

    void saveRoleBinding(ProviderContracts.AgentRoleBinding binding);
    Optional<ProviderContracts.AgentRoleBinding> findRoleBinding(String workspaceId, AgentRole role);
    List<ProviderContracts.AgentRoleBinding> listRoleBindings(String workspaceId);
}
