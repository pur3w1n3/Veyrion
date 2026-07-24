package com.aq.jvmsentinel.provider;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/**
 * Public/domain DTOs for provider configuration.
 * None of these contracts can carry plaintext secrets or encrypted credential material.
 */
public final class ProviderContracts {
    public static final int SCHEMA_VERSION = 1;

    private ProviderContracts() { }

    public record ProviderDefinition(int schemaVersion, String workspaceId, String providerId,
                                     String displayName, ProviderKind kind, URI endpoint,
                                     boolean enabled, boolean credentialConfigured,
                                     Instant createdAt, Instant updatedAt) {
        public ProviderDefinition {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            providerId = id(providerId, "providerId");
            displayName = text(displayName, "displayName", 256);
            Objects.requireNonNull(kind, "kind");
            endpoint = validatedEndpoint(endpoint, kind);
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (updatedAt.isBefore(createdAt)) throw new IllegalArgumentException("updatedAt precedes createdAt");
        }
    }

    public record ModelDefinition(int schemaVersion, String workspaceId, String modelId,
                                  String providerId, String providerModelName,
                                  int contextWindowTokens, boolean enabled,
                                  Instant createdAt, Instant updatedAt) {
        public ModelDefinition {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            modelId = id(modelId, "modelId");
            providerId = id(providerId, "providerId");
            providerModelName = text(providerModelName, "providerModelName", 512);
            if (contextWindowTokens <= 0 || contextWindowTokens > 100_000_000) {
                throw new IllegalArgumentException("contextWindowTokens is outside bounds");
            }
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (updatedAt.isBefore(createdAt)) throw new IllegalArgumentException("updatedAt precedes createdAt");
        }
    }

    public record AgentRoleBinding(int schemaVersion, String workspaceId, AgentRole agentRole,
                                   String modelId, boolean enabled, Instant updatedAt) {
        public AgentRoleBinding {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            Objects.requireNonNull(agentRole, "agentRole");
            modelId = id(modelId, "modelId");
            Objects.requireNonNull(updatedAt, "updatedAt");
        }
    }

    public enum ProviderKind {
        OPENAI_COMPATIBLE,
        AZURE_OPENAI,
        LOCAL
    }

    private static void version(int value) {
        if (value != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
    }

    static String id(String value, String name) {
        return text(value, name, 256);
    }

    private static String text(String value, String name, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    public static URI validatedEndpoint(URI value, ProviderKind kind) {
        Objects.requireNonNull(value, "endpoint");
        Objects.requireNonNull(kind, "kind");
        if (!value.isAbsolute() || value.getHost() == null || value.getRawUserInfo() != null
                || value.getRawQuery() != null || value.getRawFragment() != null) {
            throw new IllegalArgumentException(
                    "endpoint must be an absolute HTTP(S) URI without user info, query, or fragment");
        }
        String scheme = value.getScheme().toLowerCase(java.util.Locale.ROOT);
        String host = value.getHost();
        if (kind == ProviderKind.LOCAL) {
            boolean loopback = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                    || "::1".equals(host) || "0:0:0:0:0:0:0:1".equals(host);
            if (!loopback || !("http".equals(scheme) || "https".equals(scheme))) {
                throw new IllegalArgumentException("LOCAL endpoint must use loopback HTTP(S)");
            }
        } else if (!"https".equals(scheme)) {
            throw new IllegalArgumentException("remote provider endpoint must use HTTPS");
        }
        return value.normalize();
    }
}
