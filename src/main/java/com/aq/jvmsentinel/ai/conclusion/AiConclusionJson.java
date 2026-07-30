package com.aq.jvmsentinel.ai.conclusion;

import com.fasterxml.jackson.databind.ObjectMapper;

/** 结论 JSON 编码与共享 ObjectMapper。 */
public final class AiConclusionJson {
    public static final ObjectMapper JSON = new ObjectMapper();

    private AiConclusionJson() {
    }

    public static String encode(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (Exception impossible) {
            throw new IllegalStateException("could not encode bounded AI metadata", impossible);
        }
    }
}
