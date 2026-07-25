package com.aq.jvmsentinel.provider;

/** Server-owned language choice persisted with each immutable AI job snapshot. */
public enum AiOutputLanguage {
    ZH_CN,
    EN;

    public static AiOutputLanguage parse(String value) {
        if (value == null || value.isBlank()) return ZH_CN;
        try {
            return valueOf(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("unsupported AI output language");
        }
    }
}
