package com.aq.jvmsentinel.fixture;

import java.util.Map;

/**
 * Replaceable seam for tests. Production uses {@link AgentIntentRecorder}, which delegates only
 * to the explicit AgentRuntime probes.
 */
public interface IntentRecorder {
    void http(Map<String, String> detail);

    void jdbc(Map<String, String> detail);

    void file(Map<String, String> detail);

    void process(Map<String, String> detail);
}
