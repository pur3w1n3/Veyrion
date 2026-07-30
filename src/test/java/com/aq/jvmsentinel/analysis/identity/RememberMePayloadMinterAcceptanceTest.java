package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

/** RememberMe AES cookie mint for Shiro-550 sandbox observation. */
public final class RememberMePayloadMinterAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        String key = RememberMeCipherHarvester.WELL_KNOWN_SHIRO_ALT_CIPHER_KEY;
        String cookie = RememberMePayloadMinter.cookieHeader("rememberMe", key);
        check(cookie.startsWith("rememberMe="), "cookie header uses rememberMe name");
        String value = cookie.substring("rememberMe=".length());
        check(!value.isBlank() && !value.equals(SyntheticIdentityService.COOKIE_MATERIAL_MARKER),
                "minted value is not the harvest marker");
        byte[] decoded = Base64.getDecoder().decode(value);
        check(decoded.length > 16, "wire includes IV + ciphertext");

        check(RememberMePayloadMinter.mintBase64CookieValue("").isBlank(),
                "blank key yields empty mint");
        check(RememberMePayloadMinter.mintBase64CookieValue("!!!").isBlank(),
                "invalid key yields empty mint");

        System.out.println("RememberMePayloadMinterAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
