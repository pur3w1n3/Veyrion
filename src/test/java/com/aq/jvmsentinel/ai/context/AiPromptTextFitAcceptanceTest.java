package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.provider.chat.ProviderChatContracts;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/** 大上下文截断后仍可构造 UserTurn（回归 PATH user text is invalid）。 */
public final class AiPromptTextFitAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        oversizedFitsUserTurn();
        underLimitUnchanged();
        System.out.println("AiPromptTextFitAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void oversizedFitsUserTurn() {
        String huge = "路径探求上下文 ".repeat(20_000);
        check(huge.getBytes(StandardCharsets.UTF_8).length > ProviderChatContracts.MAX_TEXT_BYTES,
                "fixture exceeds MAX_TEXT_BYTES");
        String fitted = AiPromptText.fitChatUserText(huge);
        int bytes = fitted.getBytes(StandardCharsets.UTF_8).length;
        check(bytes <= ProviderChatContracts.MAX_TEXT_BYTES, "fitted within max bytes");
        check(fitted.contains("PROMPT_TRUNCATED"), "truncation marker present");
        ProviderChatContracts.UserTurn turn = new ProviderChatContracts.UserTurn(fitted);
        check(turn.text().equals(fitted), "UserTurn accepts fitted text");
    }

    private static void underLimitUnchanged() {
        String small = "ENTRY_SUMMARY short";
        check(small.equals(AiPromptText.fitChatUserText(small)), "small prompt unchanged");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
