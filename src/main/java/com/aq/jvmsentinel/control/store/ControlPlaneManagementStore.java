package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.security.auth.OperatorRole;

import javax.crypto.SecretKey;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

/** Store 辅助类。 */
public final class ControlPlaneManagementStore {
    private final SQLiteControlPlanePersistence persistence;
    private final SecretKey rootKey;
    private final ProviderSecretCipher providerCipher;
    private final ControlPlaneEntityAccess entities;

    public ControlPlaneManagementStore(SQLiteControlPlanePersistence persistence,
                                SecretKey rootKey,
                                ProviderSecretCipher providerCipher,
                                ControlPlaneEntityAccess entities) {
        this.persistence = persistence;
        this.rootKey = rootKey;
        this.providerCipher = providerCipher;
        this.entities = entities;
    }

    public void requirePersistentManagement() {
        if (persistence == null) {
            throw new IllegalStateException("management configuration requires SQLite");
        }
    }

    public void bootstrapOperator(String token, String now) {
        requirePersistentManagement();
        persistence.bootstrapOperator(token, now);
    }

    public SQLiteControlPlanePersistence.OperatorData authenticateOperator(String token) {
        return persistence == null ? null : persistence.authenticateOperator(token).orElse(null);
    }

    public List<SQLiteControlPlanePersistence.OperatorData> operators() {
        requirePersistentManagement();
        return persistence.listOperators();
    }

    public ControlPlaneStore.CreatedOperator createOperator(String username, OperatorRole role,
                                                     String actorId, String now) {
        requirePersistentManagement();
        validateManagementText(username, "username");
        Objects.requireNonNull(role, "role");
        String id = "operator-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String pat = "vyr_pat_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Arrays.fill(random, (byte) 0);
        SQLiteControlPlanePersistence.OperatorData operator =
                new SQLiteControlPlanePersistence.OperatorData(id, username, role, now, now);
        persistence.createOperator(operator, sha256(pat), actorId);
        return new ControlPlaneStore.CreatedOperator(operator, pat);
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                        String actorId, String now) {
        requirePersistentManagement();
        if (persistence.listOperators().stream().noneMatch(value -> value.operatorId().equals(operatorId))) {
            throw new ControlPlaneStore.MissingRecordException("operator not found");
        }
        persistence.updateOperator(operatorId, Objects.requireNonNull(role, "role"),
                revokeTokens, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.ProviderData> providers() {
        requirePersistentManagement();
        return persistence.listProviders();
    }

    public SQLiteControlPlanePersistence.ProviderData requireProvider(String providerId) {
        requirePersistentManagement();
        return persistence.findProvider(providerId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("provider not found"));
    }

    public SQLiteControlPlanePersistence.ProviderData saveProvider(
            String providerId, String name, ProviderContracts.ProviderKind kind, String baseUrl,
            String model, boolean enabled, String apiKey, String actorId, String now) {
        requirePersistentManagement();
        ControlPlaneStore.validateId(providerId, "providerId");
        validateManagementText(name, "name");
        URI endpoint;
        try {
            endpoint = ProviderContracts.validatedEndpoint(URI.create(baseUrl), kind);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("provider baseUrl is invalid");
        }
        SQLiteControlPlanePersistence.ProviderData existing =
                persistence.findProvider(providerId).orElse(null);
        String createdAt = existing == null ? now : existing.createdAt();
        boolean hasCredential = apiKey != null || existing != null && existing.hasCredential();
        SQLiteControlPlanePersistence.ProviderData provider =
                new SQLiteControlPlanePersistence.ProviderData(providerId, name, kind,
                        endpoint.toString(), model, enabled, createdAt, now, hasCredential);
        SQLiteControlPlanePersistence.StoredSecret secret = null;
        if (apiKey != null) {
            validateManagementText(apiKey, "apiKey");
            SQLiteControlPlanePersistence.StoredSecret existingSecret =
                    persistence.findProviderSecret(providerId).orElse(null);
            long version = existingSecret == null ? 1L
                    : existingSecret.scope().credentialVersion() + 1;
            String credentialId = existingSecret == null
                    ? "provider-api-key-" + sha256(providerId).substring(0, 32)
                    : existingSecret.scope().credentialId();
            ProviderSecretCipher.SecretScope scope = new ProviderSecretCipher.SecretScope(
                    SQLiteControlPlanePersistence.LOCAL_WORKSPACE, providerId,
                    credentialId, version);
            byte[] plaintext = apiKey.getBytes(StandardCharsets.UTF_8);
            try {
                secret = new SQLiteControlPlanePersistence.StoredSecret(
                        scope, providerCipher.encrypt(rootKey, scope, plaintext));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
        persistence.saveProvider(provider, secret, actorId);
        return requireProvider(providerId);
    }

    public void verifyProviderCredential(String providerId) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        Arrays.fill(plaintext, (byte) 0);
    }

    /**
     * 仅在 supplied 操作执行期间解密 provider 凭据。
     * 操作不得保留数组；本方法在所有退出路径上清零。
     */
    public <T> T withProviderCredential(String providerId, Function<byte[], T> operation) {
        requirePersistentManagement();
        Objects.requireNonNull(operation, "operation");
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        try {
            return operation.apply(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        requireProvider(providerId);
        persistence.deleteProvider(providerId, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.RoleBindingData> roleBindings(String projectId) {
        entities.requireProject(projectId);
        requirePersistentManagement();
        return persistence.listRoleBindings(projectId);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model,
            String promptZh, String promptEn, String actorId, String now) {
        entities.requireProject(projectId);
        requireProvider(providerId);
        validateManagementText(model, "model");
        validatePrompt(promptZh, "promptZh");
        validatePrompt(promptEn, "promptEn");
        SQLiteControlPlanePersistence.RoleBindingData binding =
                new SQLiteControlPlanePersistence.RoleBindingData(projectId, role, providerId, model, now,
                        blankToNull(promptZh), blankToNull(promptEn));
        persistence.saveRoleBinding(binding, actorId);
        return binding;
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        entities.requireProject(projectId);
        if (persistence.findRoleBinding(projectId, role).isEmpty()) {
            throw new ControlPlaneStore.MissingRecordException("role assignment not found");
        }
        persistence.deleteRoleBinding(projectId, role, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.AuditData> auditEvents(String projectId) {
        requirePersistentManagement();
        if (projectId != null) {
            entities.requireProject(projectId);
        }
        return persistence.listAudit(projectId);
    }

    public void auditChange(String projectId, String actorId, String action,
                     String targetType, String targetId, String detailsJson, String now) {
        if (persistence != null) {
            persistence.recordAudit(projectId, actorId, action, targetType, targetId, detailsJson, now);
        }
    }

    private static void validateManagementText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 4096
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static void validatePrompt(String value, String name) {
        if (value != null && (value.length() > 16_384 || value.indexOf('\0') >= 0
                || value.chars().anyMatch(ch -> Character.isISOControl(ch)
                && ch != '\n' && ch != '\r' && ch != '\t'))) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
