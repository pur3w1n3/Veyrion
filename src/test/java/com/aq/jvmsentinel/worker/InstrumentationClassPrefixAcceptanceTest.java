package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * classPrefix 须覆盖应用根，使 FORCED PathTrace 记录 Service/Util/Repository 跳转。
 */
public final class InstrumentationClassPrefixAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        commonPrefixAcrossControllers();
        stripsControllerLayer();
        primaryOnlyBroadensBeyondLeaf();
        System.out.println("InstrumentationClassPrefixAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void commonPrefixAcrossControllers() {
        ApiDtos.EntryDto primary = entry(
                "entry-ann-1", "com.kalvin.kvf.common.controller.UEditorController");
        List<ApiDtos.EntryDto> entries = List.of(
                primary,
                entry("entry-ann-2", "com.kalvin.kvf.modules.sys.controller.UserController"),
                entry("entry-ann-3", "com.kalvin.kvf.modules.schedule.controller.JobController"));
        String prefix = InstrumentationClassPrefix.resolve(primary, entries);
        check("com.kalvin.kvf".equals(prefix),
                "common prefix is com.kalvin.kvf, not leaf .controller package; got=" + prefix);
        check(!prefix.endsWith(".controller"), "prefix must not end with .controller");
    }

    private static void stripsControllerLayer() {
        String stripped = InstrumentationClassPrefix.stripTerminalLayer(
                "com.example.app.web.controller");
        check("com.example.app.web".equals(stripped)
                        || "com.example.app".equals(InstrumentationClassPrefix.broadenPrimary(
                        "com.example.app.web.controller")),
                "terminal controller layer stripped");
    }

    private static void primaryOnlyBroadensBeyondLeaf() {
        ApiDtos.EntryDto primary = entry(
                "entry-1", "com.kalvin.kvf.common.controller.UEditorController");
        String prefix = InstrumentationClassPrefix.resolve(primary, List.of(primary));
        check(prefix.startsWith("com.kalvin.kvf"),
                "single-entry prefix broadens to app root; got=" + prefix);
        check(!prefix.equals("com.kalvin.kvf.common.controller"),
                "must not keep leaf controller package alone");
    }

    private static ApiDtos.EntryDto entry(String id, String declaringClass) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p", "d".repeat(64), "scan-a",
                id, "HTTP", "GET", "/" + id, declaringClass, "m",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
