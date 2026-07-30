package com.aq.jvmsentinel.security;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/** provider credential 的 AES-256-GCM 加密，AAD 绑定 scope。 */
public final class ProviderSecretCipher {
    public static final int FORMAT_VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecureRandom random;

    public ProviderSecretCipher() {
        this(new SecureRandom());
    }

    public ProviderSecretCipher(SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    public EncryptedSecret encrypt(SecretKey rootKey, SecretScope scope, byte[] plaintext) {
        validateKey(rootKey);
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, rootKey, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(scope));
            return new EncryptedSecret(FORMAT_VERSION, scope.credentialVersion(), nonce,
                    cipher.doFinal(plaintext));
        } catch (GeneralSecurityException failure) {
            throw new SecretCipherException("provider secret encryption failed", failure);
        }
    }

    public byte[] decrypt(SecretKey rootKey, SecretScope scope, EncryptedSecret encrypted) {
        validateKey(rootKey);
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(encrypted, "encrypted");
        if (encrypted.formatVersion() != FORMAT_VERSION
                || encrypted.credentialVersion() != scope.credentialVersion()) {
            throw new SecretIntegrityException("provider secret scope or format mismatch", null);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, rootKey,
                    new GCMParameterSpec(TAG_BITS, encrypted.nonce()));
            cipher.updateAAD(aad(scope));
            return cipher.doFinal(encrypted.ciphertext());
        } catch (AEADBadTagException failure) {
            throw new SecretIntegrityException("provider secret authentication failed", failure);
        } catch (GeneralSecurityException | IllegalArgumentException failure) {
            throw new SecretIntegrityException("provider secret decryption failed closed", failure);
        }
    }

    private static byte[] aad(SecretScope scope) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(FORMAT_VERSION);
                writeBounded(output, scope.workspaceId());
                writeBounded(output, scope.providerId());
                writeBounded(output, scope.credentialId());
                output.writeLong(scope.credentialVersion());
            }
            return bytes.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new IllegalStateException("in-memory AAD encoding failed", impossible);
        }
    }

    private static void writeBounded(DataOutputStream output, String value) throws java.io.IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static void validateKey(SecretKey key) {
        Objects.requireNonNull(key, "rootKey");
        byte[] encoded = key.getEncoded();
        try {
            if (!"AES".equalsIgnoreCase(key.getAlgorithm()) || encoded == null || encoded.length != 32) {
                throw new IllegalArgumentException("rootKey must be a 256-bit AES key");
            }
        } finally {
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
        }
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > 256
                || value.chars().anyMatch(c -> Character.isISOControl(c))) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    public record SecretScope(String workspaceId, String providerId, String credentialId,
                              long credentialVersion) {
        public SecretScope {
            workspaceId = id(workspaceId, "workspaceId");
            providerId = id(providerId, "providerId");
            credentialId = id(credentialId, "credentialId");
            if (credentialVersion <= 0) throw new IllegalArgumentException("credentialVersion must be positive");
        }
    }

    public record EncryptedSecret(int formatVersion, long credentialVersion, byte[] nonce,
                                  byte[] ciphertext) {
        public EncryptedSecret {
            if (formatVersion <= 0) throw new IllegalArgumentException("formatVersion must be positive");
            if (credentialVersion <= 0) throw new IllegalArgumentException("credentialVersion must be positive");
            Objects.requireNonNull(nonce, "nonce");
            Objects.requireNonNull(ciphertext, "ciphertext");
            if (nonce.length != NONCE_BYTES) throw new IllegalArgumentException("nonce must be 96 bits");
            if (ciphertext.length < TAG_BITS / 8) throw new IllegalArgumentException("ciphertext is truncated");
            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
        }

        @Override public byte[] nonce() { return nonce.clone(); }
        @Override public byte[] ciphertext() { return ciphertext.clone(); }
        @Override public String toString() {
            return "EncryptedSecret[formatVersion=" + formatVersion
                    + ", credentialVersion=" + credentialVersion + ", redacted=true]";
        }
    }

    public static class SecretCipherException extends SecurityException {
        SecretCipherException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class SecretIntegrityException extends SecretCipherException {
        SecretIntegrityException(String message, Throwable cause) { super(message, cause); }
    }
}
