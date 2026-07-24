package com.aq.jvmsentinel.fixture;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/fixture")
public final class HttpEntryController {
    private final IntentRecorder recorder;

    public HttpEntryController(IntentRecorder recorder) {
        this.recorder = Objects.requireNonNull(recorder, "recorder");
    }

    @PostMapping(path = "/http-entry", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ProbeResponse probe(@RequestBody ProbeRequest request) {
        Objects.requireNonNull(request, "request");
        String marker = requireSyntheticMarker(request.marker());

        recorder.http(Map.of(
                "route", "POST /fixture/http-entry",
                "input", marker,
                "executed", "false",
                "mode", "DIRECT_CONTROLLER_INVOCATION"));
        recorder.jdbc(Map.of(
                "operation", "SIMULATED_SELECT",
                "target", "synthetic.fixture_record",
                "executed", "false"));
        recorder.file(Map.of(
                "operation", "SIMULATED_READ",
                "target", "synthetic://fixture/input",
                "executed", "false"));
        recorder.process(Map.of(
                "operation", "SIMULATED_SPAWN",
                "target", "synthetic-noop",
                "executed", "false"));

        return new ProbeResponse("RECORDED", marker);
    }

    private static String requireSyntheticMarker(String marker) {
        if (marker == null || !marker.matches("synthetic-[a-z0-9-]{1,48}")) {
            throw new IllegalArgumentException("marker must be a bounded synthetic value");
        }
        return marker;
    }

    public record ProbeRequest(String marker) { }

    public record ProbeResponse(String status, String marker) { }
}
