package com.aq.jvmsentinel.provider;

/** 服务端拥有的语言选择，与每个不可变 AI job snapshot 一并持久化。 */
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
