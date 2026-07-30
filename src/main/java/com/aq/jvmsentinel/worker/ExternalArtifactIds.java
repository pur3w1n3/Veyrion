package com.aq.jvmsentinel.worker;

import java.util.Objects;

/** 外部制品执行器共用的标识符校验。 */
public final class ExternalArtifactIds {
    private ExternalArtifactIds() { }

    public static String requireId(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }
}
