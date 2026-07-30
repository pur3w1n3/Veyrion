package com.aq.jvmsentinel.analysis.identity;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 从 authorized artifact harvest 的 channel-agnostic identity 材料。
 * 不提升 verification status；value 字节留在 mint/apply path 内部。
 */
public record IdentityMaterial(
        IdentityMaterialKind kind,
        AuthChannel channel,
        String name,
        String valueProvenance,
        String alias,
        Optional<String> value,
        List<String> guardRefs,
        String sourcePath
) {
    public IdentityMaterial {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(channel, "channel");
        name = name == null ? "" : name.trim();
        valueProvenance = valueProvenance == null || valueProvenance.isBlank()
                ? "RULE_GENERATED" : valueProvenance.trim();
        alias = alias == null ? "" : alias.trim();
        value = value == null ? Optional.empty() : value;
        guardRefs = List.copyOf(guardRefs == null ? List.of() : guardRefs);
        sourcePath = sourcePath == null ? "" : sourcePath;
    }

    public boolean hasValue() {
        return value.isPresent() && !value.get().isBlank();
    }
}
