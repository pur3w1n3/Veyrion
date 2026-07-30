package com.aq.jvmsentinel.security;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * 加密 provider credential 的 persistence 边界。
 * 实现不得存储 root key 或通过 public API DTO 暴露 record。
 */
public interface ProviderCredentialRepository {
    void save(StoredCredential credential);
    Optional<StoredCredential> find(String workspaceId, String providerId, String credentialId);
    void delete(String workspaceId, String providerId, String credentialId);

    record StoredCredential(ProviderSecretCipher.SecretScope scope,
                            ProviderSecretCipher.EncryptedSecret encryptedSecret,
                            Instant updatedAt) {
        public StoredCredential {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(encryptedSecret, "encryptedSecret");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (scope.credentialVersion() != encryptedSecret.credentialVersion()) {
                throw new IllegalArgumentException("credential version mismatch");
            }
        }

        @Override public String toString() {
            return "StoredCredential[scope=" + scope + ", encryptedSecret=REDACTED, updatedAt="
                    + updatedAt + "]";
        }
    }
}
