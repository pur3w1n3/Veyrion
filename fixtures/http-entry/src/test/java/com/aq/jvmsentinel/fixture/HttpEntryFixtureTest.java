package com.aq.jvmsentinel.fixture;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpEntryFixtureTest {
    @Test
    void startsSpringContextInvokesProbeOnceAndCloses() {
        RecordingIntentRecorder recorder = new RecordingIntentRecorder();

        HttpEntryFixture.RunResult result = HttpEntryFixture.runOnce(recorder);

        assertEquals(0, result.exitCode());
        assertTrue(result.contextStarted());
        assertTrue(result.contextClosed());
        assertEquals(List.of("HTTP", "JDBC", "FILE", "PROCESS"), recorder.types);
        assertTrue(recorder.details.stream().allMatch(detail -> "false".equals(detail.get("executed"))));
    }

    @Test
    void exposesRealControllerAndPostMappingAnnotations() throws Exception {
        assertNotNull(HttpEntryController.class.getAnnotation(RestController.class));
        RequestMapping base = HttpEntryController.class.getAnnotation(RequestMapping.class);
        assertArrayEquals(new String[]{"/fixture"}, base.value());

        Method probe = HttpEntryController.class.getMethod(
                "probe", HttpEntryController.ProbeRequest.class);
        PostMapping mapping = probe.getAnnotation(PostMapping.class);
        assertNotNull(mapping);
        assertArrayEquals(new String[]{"/http-entry"}, mapping.path());
    }

    @Test
    void harmlessProbeUsesReplaceableRecorder() {
        RecordingIntentRecorder recorder = new RecordingIntentRecorder();
        HttpEntryController controller = new HttpEntryController(recorder);

        HttpEntryController.ProbeResponse response =
                controller.probe(new HttpEntryController.ProbeRequest("synthetic-test"));

        assertEquals("RECORDED", response.status());
        assertEquals("synthetic-test", response.marker());
        assertEquals(List.of("HTTP", "JDBC", "FILE", "PROCESS"), recorder.types);
    }

    private static final class RecordingIntentRecorder implements IntentRecorder {
        private final List<String> types = new ArrayList<>();
        private final List<Map<String, String>> details = new ArrayList<>();

        @Override public void http(Map<String, String> detail) { add("HTTP", detail); }
        @Override public void jdbc(Map<String, String> detail) { add("JDBC", detail); }
        @Override public void file(Map<String, String> detail) { add("FILE", detail); }
        @Override public void process(Map<String, String> detail) { add("PROCESS", detail); }

        private void add(String type, Map<String, String> detail) {
            types.add(type);
            details.add(detail);
        }
    }
}
