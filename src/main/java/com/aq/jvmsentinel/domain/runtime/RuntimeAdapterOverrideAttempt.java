package com.aq.jvmsentinel.domain.runtime;

import java.util.List;
import java.util.Optional;

/**
 * 来自 model / frontend / Analyzer 的不可信 override 尝试。
 * 任何 present field 必须导致 fail-closed 拒绝。
 */
public record RuntimeAdapterOverrideAttempt(
        Optional<String> commandOverride,
        Optional<String> imageOverride,
        Optional<String> mountOverride,
        Optional<Integer> uidOverride,
        Optional<String> networkOverride,
        Optional<Long> budgetOverride
) {
    public RuntimeAdapterOverrideAttempt {
        commandOverride = commandOverride == null ? Optional.empty() : commandOverride;
        imageOverride = imageOverride == null ? Optional.empty() : imageOverride;
        mountOverride = mountOverride == null ? Optional.empty() : mountOverride;
        uidOverride = uidOverride == null ? Optional.empty() : uidOverride;
        networkOverride = networkOverride == null ? Optional.empty() : networkOverride;
        budgetOverride = budgetOverride == null ? Optional.empty() : budgetOverride;
    }

    public static RuntimeAdapterOverrideAttempt none() {
        return new RuntimeAdapterOverrideAttempt(
                Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty());
    }

    public boolean hasAnyOverride() {
        return commandOverride.isPresent()
                || imageOverride.isPresent()
                || mountOverride.isPresent()
                || uidOverride.isPresent()
                || networkOverride.isPresent()
                || budgetOverride.isPresent();
    }

    public List<String> overrideFields() {
        java.util.ArrayList<String> fields = new java.util.ArrayList<>();
        commandOverride.ifPresent(v -> fields.add("command"));
        imageOverride.ifPresent(v -> fields.add("image"));
        mountOverride.ifPresent(v -> fields.add("mount"));
        uidOverride.ifPresent(v -> fields.add("uid"));
        networkOverride.ifPresent(v -> fields.add("network"));
        budgetOverride.ifPresent(v -> fields.add("budget"));
        return List.copyOf(fields);
    }
}
