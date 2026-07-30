package com.aq.jvmsentinel.provider;

import java.util.List;
import java.util.Optional;

/**
 * workspace 作用域的 provider/model 配置 persistence。
 * 刻意不含 credential 材料；请单独使用 ProviderCredentialRepository。
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
