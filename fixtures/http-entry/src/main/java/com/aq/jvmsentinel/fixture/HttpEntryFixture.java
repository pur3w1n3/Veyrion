package com.aq.jvmsentinel.fixture;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import java.util.Map;
import java.util.Objects;

@SpringBootApplication
public class HttpEntryFixture {
    public static void main(String[] args) {
        System.exit(runOnce(new AgentIntentRecorder()).exitCode());
    }

    static RunResult runOnce(IntentRecorder recorder) {
        Objects.requireNonNull(recorder, "recorder");
        SpringApplication application = new SpringApplication(HttpEntryFixture.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setDefaultProperties(Map.of(
                "spring.main.banner-mode", "off",
                "logging.level.root", "OFF"));
        application.addInitializers(context ->
                ((GenericApplicationContext) context).registerBean(
                        IntentRecorder.class, () -> recorder));

        ConfigurableApplicationContext context = application.run();
        boolean started = context.isActive()
                && context.containsBean("httpEntryController")
                && context.containsBean("controlledProbeRunner");
        int exitCode = SpringApplication.exit(context);
        context.close();
        return new RunResult(exitCode, started, !context.isActive());
    }

    record RunResult(int exitCode, boolean contextStarted, boolean contextClosed) { }
}
