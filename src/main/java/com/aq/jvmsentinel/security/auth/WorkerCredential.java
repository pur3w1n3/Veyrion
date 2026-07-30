package com.aq.jvmsentinel.security.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * 无 operator role 或 permission 的机器 credential。
 * 刻意不能转换为或继承 AuthContext。
 */
public final class WorkerCredential implements AutoCloseable {
    private final String credentialId;
    private byte[] token;

    public WorkerCredential(String credentialId, byte[] token) {
        this.credentialId = id(credentialId);
        Objects.requireNonNull(token, "token");
        if (token.length < 32 || token.length > 4096) {
            throw new IllegalArgumentException("worker token must contain 32..4096 bytes");
        }
        this.token = token.clone();
    }

    public static WorkerCredential utf8(String credentialId, String token) {
        Objects.requireNonNull(token, "token");
        return new WorkerCredential(credentialId, token.getBytes(StandardCharsets.UTF_8));
    }

    public String credentialId() { return credentialId; }

    public synchronized boolean matches(byte[] candidate) {
        if (token == null || candidate == null) return false;
        return MessageDigest.isEqual(token, candidate);
    }

    public synchronized boolean destroyed() { return token == null; }

    @Override public synchronized void close() {
        if (token != null) {
            Arrays.fill(token, (byte) 0);
            token = null;
        }
    }

    @Override public String toString() {
        return "WorkerCredential[credentialId=" + credentialId + ", token=REDACTED]";
    }

    private static String id(String value) {
        Objects.requireNonNull(value, "credentialId");
        if (value.isBlank() || value.length() > 256
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("credentialId is invalid");
        }
        return value;
    }
}
