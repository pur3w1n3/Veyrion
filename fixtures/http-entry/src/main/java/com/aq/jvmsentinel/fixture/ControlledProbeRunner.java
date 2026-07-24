package com.aq.jvmsentinel.fixture;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
final class ControlledProbeRunner implements ApplicationRunner {
    static final String SYNTHETIC_MARKER = "synthetic-http-entry-v1";

    private final HttpEntryController controller;

    ControlledProbeRunner(HttpEntryController controller) {
        this.controller = controller;
    }

    @Override
    public void run(ApplicationArguments args) {
        HttpEntryController.ProbeResponse response =
                controller.probe(new HttpEntryController.ProbeRequest(SYNTHETIC_MARKER));
        if (!"RECORDED".equals(response.status())) {
            throw new IllegalStateException("controlled probe did not complete");
        }
    }
}
