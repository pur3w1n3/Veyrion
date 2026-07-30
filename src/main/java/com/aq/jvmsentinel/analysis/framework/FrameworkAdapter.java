package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 可选 framework 特定 route / auth <em>hint</em> 的 SPI。
 * Adapter 仅贡献 signal；control plane、identity mint path 与 AUTH
 * pipeline 保持 JVM-generic，不得将任一 framework 视为 first-class。
 */
public interface FrameworkAdapter {
    String id();

    boolean matches(Path artifactPath, List<String> routes);

    Set<String> highValueRouteSignals();

    Set<String> highValueClassSignals();

    /**
     * 为 true 时，probe 除
     * {@code Authorization}. Header name comes from {@link #secondaryAuthHeaderName()}.
     */
    boolean preferSecondaryAuthHeader(SyntheticIdentityService.MaterialBundle materials);

    /**
     * 建议次要 HTTP header 名（如 {@code Blade-Auth}）当
     * {@link #preferSecondaryAuthHeader} is true; empty means Authorization-only.
     */
    default String secondaryAuthHeaderName() {
        return "";
    }

    /**
     * 可选 adapter-owned detection dictionary，用于 known weak / historical sign-key
     * 字符串。仅当相同字节出现在 authorized artifact 内时使用；
     * 永非 silent mint source。Classification 保持 RULE_GENERATED / HINT。
     */
    default List<AuthCodeQueryService.WellKnownKey> wellKnownSecretHints() {
        return List.of();
    }

    /**
     * 提示本 adapter auth 面的额外 archive path 片段
     * (e.g. {@code org/springblade/core/secure}). Merged into generic code_query scans.
     */
    default Set<String> authClassPathSignals() {
        return Set.of();
    }

    /**
     * 可选 redacted harvest signal 供 dashboard/AI。不得返回 raw commercial
     * default 当作 FACT；HINT 注入优先 {@link #jwtSecretHintNotes()}。
     */
    Optional<String> suggestJwtSecret(Path artifactPath);

    /**
     * 说明：FRAMEWORK_ADAPTER_CONTEXT well-known/framework HINT note（非 FACT，非 mint）。
     */
    default List<String> jwtSecretHintNotes() {
        return List.of();
    }

    List<AuthBypassTechnique> defaultBypassTechniques();

    /** @deprecated Use {@link #preferSecondaryAuthHeader}; Blade-named SPI retained for tests. */
    @Deprecated
    default boolean preferBladeAuthHeader(SyntheticIdentityService.MaterialBundle materials) {
        return preferSecondaryAuthHeader(materials);
    }
}
