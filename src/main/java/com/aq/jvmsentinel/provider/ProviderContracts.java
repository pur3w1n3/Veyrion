package com.aq.jvmsentinel.provider;

import java.net.URI;
import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * provider 配置的 public/domain DTO。
 * 这些 contract 均不能携带明文 secret 或加密 credential 材料。
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
            if (contextWindowTokens < 0 || contextWindowTokens > 100_000_000) {
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
        /** 显式 OpenAI Chat Completions protocol。 */
        OPENAI_CHAT(ProviderProtocol.OPENAI_CHAT),
        /** 显式 Anthropic Messages protocol。 */
        ANTHROPIC_MESSAGES(ProviderProtocol.ANTHROPIC_MESSAGES),
        /** Legacy 持久化值；protocol 与 OPENAI_CHAT 兼容。 */
        @Deprecated
        OPENAI_COMPATIBLE(ProviderProtocol.OPENAI_CHAT),
        /** Legacy 持久化值。Azure routing 不能从 OpenAI protocol 推断。 */
        AZURE_OPENAI(null),
        /** 现有仅 loopback 兼容边界；使用 OpenAI wire shape。 */
        LOCAL(ProviderProtocol.OPENAI_CHAT);

        private final ProviderProtocol protocol;

        ProviderKind(ProviderProtocol protocol) {
            this.protocol = protocol;
        }

        public ProviderProtocol protocol() {
            if (protocol == null) {
                throw new IllegalStateException("provider kind has no safe inventory protocol");
            }
            return protocol;
        }
    }

    public enum ProviderProtocol {
        OPENAI_CHAT("/v1/models", "after"),
        ANTHROPIC_MESSAGES("/v1/models", "after_id");

        private final String modelsPath;
        private final String cursorParameter;

        ProviderProtocol(String modelsPath, String cursorParameter) {
            this.modelsPath = modelsPath;
            this.cursorParameter = cursorParameter;
        }

        public String modelsPath() {
            return modelsPath;
        }

        public String cursorParameter() {
            return cursorParameter;
        }
    }

    /**
     * 远程 inventory 仅为 discovery 数据。既不 allowlist model，也不证明
     * 说明：chat/tool-use/structured-output/context-window 或其他 runtime capability。
     */
    public record ModelInventory(int schemaVersion, String workspaceId, String providerId,
                                 ProviderProtocol protocol, List<ModelDefinition> models,
                                 InventorySemantics semantics, Instant fetchedAt) {
        public ModelInventory {
            version(schemaVersion);
            workspaceId = id(workspaceId, "workspaceId");
            providerId = id(providerId, "providerId");
            Objects.requireNonNull(protocol, "protocol");
            models = List.copyOf(Objects.requireNonNull(models, "models"));
            semantics = Objects.requireNonNull(semantics, "semantics");
            Objects.requireNonNull(fetchedAt, "fetchedAt");
            if (semantics != InventorySemantics.REMOTE_INVENTORY_ONLY) {
                throw new IllegalArgumentException("remote inventory semantics are fixed");
            }
            for (ModelDefinition model : models) {
                if (!workspaceId.equals(model.workspaceId()) || !providerId.equals(model.providerId())
                        || model.enabled() || model.contextWindowTokens() != 0) {
                    throw new IllegalArgumentException("inventory model must be unallowlisted with unknown context");
                }
            }
        }
    }

    public enum InventorySemantics {
        REMOTE_INVENTORY_ONLY
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
        String scheme = value.getScheme().toLowerCase(Locale.ROOT);
        String host = value.getHost();
        boolean loopback = isLoopbackHost(host);
        if (kind == ProviderKind.LOCAL) {
            if (!loopback || !("http".equals(scheme) || "https".equals(scheme))) {
                throw new IllegalArgumentException("LOCAL endpoint must use loopback HTTP(S)");
            }
        } else if (loopback) {
            if (!("http".equals(scheme) || "https".equals(scheme))) {
                throw new IllegalArgumentException("loopback provider endpoint must use HTTP(S)");
            }
        } else {
            if (!("http".equals(scheme) || "https".equals(scheme))) {
                throw new IllegalArgumentException("provider endpoint must use HTTP(S)");
            }
            if (forbiddenRemoteHost(host)) {
                throw new IllegalArgumentException("provider endpoint targets a forbidden host");
            }
        }
        return value.normalize();
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                || "::1".equals(host) || "0:0:0:0:0:0:0:1".equals(host);
    }

    private static boolean forbiddenRemoteHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if ("localhost".equals(normalized) || normalized.endsWith(".localhost")
                || "metadata.google.internal".equals(normalized)) {
            return true;
        }
        if (normalized.indexOf(':') >= 0) {
            try {
                InetAddress address = InetAddress.getByName(normalized);
                return address.isAnyLocalAddress() || address.isLoopbackAddress()
                        || address.isLinkLocalAddress() || address.isMulticastAddress();
            } catch (Exception invalidLiteral) {
                return true;
            }
        }
        String[] parts = normalized.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].isEmpty() || parts[i].length() > 3
                    || !parts[i].chars().allMatch(Character::isDigit)) {
                return false;
            }
            octets[i] = Integer.parseInt(parts[i]);
            if (octets[i] > 255) return true;
        }
        int first = octets[0];
        int second = octets[1];
        return first == 0 || first == 127
                || first == 169 && second == 254
                || first >= 224;
    }
}
