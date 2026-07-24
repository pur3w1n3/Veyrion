package com.aq.jvmsentinel.security;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Persistence boundary for encrypted provider credentials.
 * Implementations must never store a root key or expose records through public API DTOs.
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
