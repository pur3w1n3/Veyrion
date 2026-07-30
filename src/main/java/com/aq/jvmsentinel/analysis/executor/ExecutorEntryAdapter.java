package com.aq.jvmsentinel.analysis.executor;

import java.util.List;
import java.util.Set;

/**
 * 插件式运行时回调 / Executor 入口适配器。
 * 仅贡献证据驱动的 Entry 候选；不得发明权限、沙箱命令或验证态提升。
 *
 * <p>对齐 {@link com.aq.jvmsentinel.analysis.framework.FrameworkAdapter} 的
 * registry/SPI 风格，但面向「非典型 MVC 业务页、进程内回调口」探测面。
 */
public interface ExecutorEntryAdapter {
    /** Stable adapter id，如 {@code xxl-job-executor}。 */
    String id();

    /** Framework 族标识，写入 entry preconditions（{@code framework:<id>}）。 */
    String frameworkId();

    /** 证据命中时返回 true；未命中不得产出入口。 */
    boolean matches(ExecutorEntryContext context);

    /**
     * 在 {@link #matches} 为 true 时产出回调入口候选。
     * HTTP 族可进入 TracePlan / 动态探针；非 HTTP 应使用可观测 protocol（如 JOB），
     * 且不得硬造虚假 MVC 路由。
     */
    List<RuntimeCallbackEntry> discover(ExecutorEntryContext context);

    /** 高价值 route 子串（小写比较），供探针优先排序。 */
    default Set<String> highValueRouteSignals() {
        return Set.of();
    }

    /** 高价值 class / archive 子串。 */
    default Set<String> highValueClassSignals() {
        return Set.of();
    }
}
