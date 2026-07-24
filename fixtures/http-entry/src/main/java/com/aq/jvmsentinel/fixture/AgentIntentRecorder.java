package com.aq.jvmsentinel.fixture;

import com.aq.jvmsentinel.instrumentation.AgentRuntime;

import java.util.Map;

final class AgentIntentRecorder implements IntentRecorder {
    private static final String CLASS_NAME = HttpEntryController.class.getName();
    private static final String METHOD_NAME = "probe";

    @Override
    public void http(Map<String, String> detail) {
        AgentRuntime.recordHttp(CLASS_NAME, METHOD_NAME, detail);
    }

    @Override
    public void jdbc(Map<String, String> detail) {
        AgentRuntime.recordJdbc(CLASS_NAME, METHOD_NAME, detail);
    }

    @Override
    public void file(Map<String, String> detail) {
        AgentRuntime.recordFile(CLASS_NAME, METHOD_NAME, detail);
    }

    @Override
    public void process(Map<String, String> detail) {
        AgentRuntime.recordProcess(CLASS_NAME, METHOD_NAME, detail);
    }
}
