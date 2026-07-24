package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.OpenSandboxClient;
import com.aq.jvmsentinel.sandbox.OpenSandboxConfig;
import com.aq.jvmsentinel.sandbox.RuntimeAttestation;

import java.io.PrintStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Fail-closed execute-one entry point for a catalog-owned fixture task.
 *
 * <p>This launcher does not list or poll tasks and has no host-process fallback.</p>
 */
public final class FixtureWorkerMain {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final long MAX_TRACE_INPUT_BYTES = 1024L * 1024;
    private static final int MAX_TRACE_LINE_BYTES = 64 * 1024;
    private static final int MAX_TRACE_LINES = 10_000;
    private static final int MAX_TRACE_CHUNK_BYTES = 256 * 1024;
    private static final Set<String> REQUIRED_FEATURES = Set.of(
            "lifecycle-v1", "execd-command-v1", "network-deny-v1",
            "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1",
            "writable-tmp-v1");

    private FixtureWorkerMain() { }

    public static void main(String[] args) {
        if (args.length != 0) {
            System.err.println(errorJson("ARGUMENTS_REJECTED"));
            System.exit(2);
            return;
        }
        try {
            Configuration configuration = Configuration.load(System.getenv(), System.getProperties());
            executeOne(configuration, System.out);
        } catch (RuntimeException failure) {
            System.err.println(errorJson(failure instanceof ConfigurationException
                    ? "CONFIGURATION_REJECTED" : "EXECUTION_FAILED"));
            System.exit(1);
        }
    }

    static FixtureTaskExecutor.ExecutionResult executeOne(Configuration configuration, PrintStream output) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(output, "output");
        WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                configuration.controlBaseUri, configuration.workerToken, REQUEST_TIMEOUT);
        OpenSandboxConfig sandboxConfig = new OpenSandboxConfig(
                configuration.lifecycleBaseUri, configuration.apiKey, configuration.execdToken,
                REQUEST_TIMEOUT, configuration.protocol,
                new RuntimeAttestation(configuration.protocol, WorkerCapability.FIXTURE_RUNC, "runc",
                        true, true, true, REQUIRED_FEATURES));
        OpenSandboxClient sandbox = new OpenSandboxClient(sandboxConfig);
        AgentJsonlTraceConverter converter = new AgentJsonlTraceConverter(
                Clock.systemUTC(), MAX_TRACE_INPUT_BYTES, MAX_TRACE_LINE_BYTES,
                MAX_TRACE_LINES, MAX_TRACE_CHUNK_BYTES);
        FixtureTaskExecutor executor =
                new FixtureTaskExecutor(control, sandbox, converter, configuration.workerId);
        FixtureTaskExecutor.ExecutionResult result =
                executor.execute(new FixtureTaskExecutor.ExecutionRequest(configuration.scope));
        output.println(summaryJson(result));
        return result;
    }

    static String summaryJson(FixtureTaskExecutor.ExecutionResult result) {
        Objects.requireNonNull(result, "result");
        return JsonCodec.stringify(Map.of(
                "taskId", result.scope().taskId(),
                "lifecycle", result.lifecycle().name(),
                "traceChunks", result.traceChunks(),
                "headDigest", result.traceHeadDigest()));
    }

    private static String errorJson(String code) {
        return JsonCodec.stringify(Map.of("status", "FAILED", "code", code));
    }

    /**
     * Immutable trusted deployment configuration. Its string form never exposes credentials.
     */
    static final class Configuration {
        private final URI controlBaseUri;
        private final String workerToken;
        private final TaskScope scope;
        private final String workerId;
        private final URI lifecycleBaseUri;
        private final String apiKey;
        private final String execdToken;
        private final String protocol;

        private Configuration(URI controlBaseUri, String workerToken, TaskScope scope, String workerId,
                              URI lifecycleBaseUri, String apiKey, String execdToken, String protocol) {
            this.controlBaseUri = controlBaseUri;
            this.workerToken = workerToken;
            this.scope = scope;
            this.workerId = workerId;
            this.lifecycleBaseUri = lifecycleBaseUri;
            this.apiKey = apiKey;
            this.execdToken = execdToken;
            this.protocol = protocol;
        }

        static Configuration load(Map<String, String> environment, Properties properties) {
            Objects.requireNonNull(environment, "environment");
            Objects.requireNonNull(properties, "properties");
            ValueSource values = new ValueSource(environment, properties);
            URI controlBase = uri(values.required(
                    "VEYRION_CONTROL_INTERNAL_BASE_URI", "veyrion.worker.controlBaseUri"),
                    "Control Plane internal base URI");
            String workerToken = secret(values.required(
                    "VEYRION_WORKER_TOKEN", "veyrion.worker.token"), "worker token");
            TaskScope scope = scope(values);
            String workerId = id(values.required(
                    "VEYRION_WORKER_ID", "veyrion.worker.id"), "workerId");
            URI lifecycleBase = uri(values.required(
                    "VEYRION_OPENSANDBOX_LIFECYCLE_URI", "veyrion.opensandbox.lifecycleUri"),
                    "OpenSandbox lifecycle URI");
            String apiKey = secret(values.required(
                    "VEYRION_OPENSANDBOX_API_KEY", "veyrion.opensandbox.apiKey"),
                    "OpenSandbox API key");
            String execdToken = secret(values.required(
                    "VEYRION_OPENSANDBOX_EXECD_TOKEN", "veyrion.opensandbox.execdToken"),
                    "OpenSandbox Execd token");
            String protocol = boundedText(values.required(
                    "VEYRION_OPENSANDBOX_ATTESTATION_PROTOCOL",
                    "veyrion.opensandbox.attestation.protocol"), "attestation protocol", 32);
            String runtime = boundedText(values.required(
                    "VEYRION_OPENSANDBOX_ATTESTATION_RUNTIME",
                    "veyrion.opensandbox.attestation.runtime"), "attestation runtime", 128);
            if (!runtime.equalsIgnoreCase("runc")) {
                throw new ConfigurationException("attestation runtime must be runc");
            }
            String capability = values.required(
                    "VEYRION_OPENSANDBOX_ATTESTATION_CAPABILITY",
                    "veyrion.opensandbox.attestation.capability");
            if (!capability.equals(WorkerCapability.FIXTURE_RUNC.name())) {
                throw new ConfigurationException("attestation capability must be FIXTURE_RUNC");
            }
            Set<String> features = features(values.required(
                    "VEYRION_OPENSANDBOX_ATTESTATION_FEATURES",
                    "veyrion.opensandbox.attestation.features"));
            if (!features.equals(REQUIRED_FEATURES)) {
                throw new ConfigurationException("attestation features do not match fixture isolation requirements");
            }
            return new Configuration(controlBase, workerToken, scope, workerId,
                    lifecycleBase, apiKey, execdToken, protocol);
        }

        private static TaskScope scope(ValueSource values) {
            try {
                return new TaskScope(
                        values.required("VEYRION_PROJECT_ID", "veyrion.worker.projectId"),
                        values.required("VEYRION_ARTIFACT_DIGEST", "veyrion.worker.artifactDigest"),
                        values.required("VEYRION_SCAN_ID", "veyrion.worker.scanId"),
                        values.required("VEYRION_TASK_ID", "veyrion.worker.taskId"));
            } catch (IllegalArgumentException | NullPointerException invalid) {
                throw new ConfigurationException("task scope is invalid");
            }
        }

        @Override
        public String toString() {
            return "FixtureWorkerConfiguration[controlBaseUri=" + controlBaseUri
                    + ", workerToken=<redacted>, scope=" + scope + ", workerId=" + workerId
                    + ", lifecycleBaseUri=" + lifecycleBaseUri
                    + ", apiKey=<redacted>, execdToken=<redacted>, protocol=" + protocol + "]";
        }
    }

    private record ValueSource(Map<String, String> environment, Properties properties) {
        private String required(String environmentName, String propertyName) {
            String property = properties.getProperty(propertyName);
            String value = property != null ? property : environment.get(environmentName);
            if (value == null || value.isBlank()) {
                throw new ConfigurationException("required configuration is missing: " + environmentName);
            }
            return value;
        }
    }

    private static URI uri(String value, String name) {
        try {
            URI uri = URI.create(value);
            if (!uri.isAbsolute()) throw new IllegalArgumentException();
            return uri;
        } catch (IllegalArgumentException invalid) {
            throw new ConfigurationException(name + " is invalid");
        }
    }

    private static String secret(String value, String name) {
        if (value.isBlank() || value.length() > 4096
                || value.chars().anyMatch(c -> c < 0x21 || c == 0x7f)) {
            throw new ConfigurationException(name + " is invalid");
        }
        return value;
    }

    private static String id(String value, String name) {
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new ConfigurationException(name + " is invalid");
        }
        return value;
    }

    private static String boundedText(String value, String name, int maximum) {
        if (value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new ConfigurationException(name + " is invalid");
        }
        return value;
    }

    private static Set<String> features(String value) {
        try {
            String[] parts = value.split(",", -1);
            if (parts.length == 0 || parts.length > 64
                    || Arrays.stream(parts).anyMatch(String::isBlank)) {
                throw new IllegalArgumentException();
            }
            Set<String> result = Arrays.stream(parts).map(String::trim)
                    .map(feature -> boundedText(feature, "attestation feature", 128))
                    .collect(Collectors.toUnmodifiableSet());
            if (result.size() != parts.length) throw new IllegalArgumentException();
            return result;
        } catch (IllegalArgumentException invalid) {
            throw new ConfigurationException("attestation features are invalid");
        }
    }

    static final class ConfigurationException extends IllegalArgumentException {
        private ConfigurationException(String message) {
            super(message);
        }
    }
}
