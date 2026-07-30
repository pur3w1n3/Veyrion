package com.aq.jvmsentinel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-23：响应式/长文本 layout contract — TS + CSS 声明 max-width，
 * overflow 与 word-break 规则供窄 viewport。
 * 审计 scope = contract test（非手动 visual regression）。
 */
public final class GuiLayoutContractAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        Path root = GuiSemanticsContractAcceptanceTest.projectRoot();
        String contract = Files.readString(root.resolve("frontend/src/layoutContract.ts"),
                StandardCharsets.UTF_8);
        String css = Files.readString(root.resolve("frontend/src/styles.css"), StandardCharsets.UTF_8);
        String main = Files.readString(root.resolve("frontend/src/main.tsx"), StandardCharsets.UTF_8);

        layoutContractDeclaresBounds(contract);
        cssDeclaresVarsAndRules(css);
        narrowClassWired(main, css, contract);

        System.out.println("GuiLayoutContractAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void layoutContractDeclaresBounds(String contract) {
        check(contract.contains("LAYOUT_CONTRACT"), "layoutContract exports LAYOUT_CONTRACT");
        check(contract.contains("contentMaxWidthPx"), "content max-width px declared");
        check(contract.contains("narrowBreakpointPx"), "narrow breakpoint declared");
        check(contract.contains("maxWidth") || contract.contains("'max-width'")
                        || contract.contains("\"max-width\""),
                "requiredRules mentions max-width");
        check(contract.contains("overflow"), "requiredRules mentions overflow");
        check(contract.contains("word-break") || contract.contains("wordBreak"),
                "requiredRules mentions word-break");
        check(contract.contains("veyrion-narrow"), "narrow viewport class name present");
        check(contract.contains("--veyrion-content-max-width"), "CSS var name for max-width");
        for (String cls : List.of("veyrion-long-text", "chat-markdown", "ai-report")) {
            check(contract.contains(cls), "long-text class " + cls + " in contract");
        }
    }

    private static void cssDeclaresVarsAndRules(String css) {
        check(css.contains("--veyrion-content-max-width"), "CSS defines content max-width var");
        check(css.contains("--veyrion-narrow-breakpoint"), "CSS defines narrow breakpoint var");
        check(css.contains("--veyrion-long-text-overflow"), "CSS defines long-text overflow var");
        check(css.contains("--veyrion-long-text-word-break"), "CSS defines word-break var");
        check(css.contains("max-width"), "CSS contains max-width rule");
        check(css.contains("overflow-x") || css.contains("overflow:"),
                "CSS contains overflow rule");
        check(css.contains("word-break") || css.contains("overflow-wrap"),
                "CSS contains word-break / overflow-wrap");
        check(css.contains(".veyrion-long-text"), "CSS defines .veyrion-long-text");
        check(css.contains(".veyrion-narrow") || css.contains("veyrion-narrow"),
                "CSS references narrow class");
        check(css.contains("@media (max-width: 760px)"),
                "CSS keeps narrow media query at 760px");
    }

    private static void narrowClassWired(String main, String css, String contract) {
        check(main.contains("layoutContract"), "main.tsx imports layoutContract");
        check(main.contains("NARROW_VIEWPORT_CLASS") || main.contains("veyrion-narrow"),
                "main.tsx applies narrow class");
        check(main.contains("matchMedia"), "main.tsx syncs narrow class via matchMedia");
        check(css.contains("overflow-wrap: anywhere") || css.contains("word-break: break-word"),
                "narrow/long-text surfaces wrap long tokens");
        check(contract.contains("760") && css.contains("760px"),
                "TS/CSS narrow breakpoint stay aligned at 760");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
