package com.aq.jvmsentinel.sandbox;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/** Connection settings. Secrets are deliberately excluded from accessors and string representations. */
public final class OpenSandboxConfig {
    private final URI lifecycleBaseUri;
    private final String apiKey;
    private final String execdAccessToken;
    private final Duration requestTimeout;
    private final String requiredProtocolVersion;
    private final RuntimeAttestation runtimeAttestation;

    public OpenSandboxConfig(URI lifecycleBaseUri, String apiKey, String execdAccessToken, Duration requestTimeout,
                             String requiredProtocolVersion, RuntimeAttestation runtimeAttestation) {
        this.lifecycleBaseUri = SandboxContracts.httpBase(lifecycleBaseUri, "lifecycleBaseUri");
        this.apiKey = secret(apiKey, "apiKey");
        this.execdAccessToken = secret(execdAccessToken, "execdAccessToken");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        if (requestTimeout.isZero() || requestTimeout.isNegative() || requestTimeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("requestTimeout must be positive and at most five minutes");
        }
        this.requiredProtocolVersion = SandboxContracts.text(requiredProtocolVersion, "requiredProtocolVersion", 32);
        this.runtimeAttestation = Objects.requireNonNull(runtimeAttestation, "runtimeAttestation");
        if (!this.requiredProtocolVersion.equals(runtimeAttestation.protocolVersion())) {
            throw new IllegalArgumentException("runtime attestation protocol mismatch");
        }
    }

    public URI lifecycleBaseUri() { return lifecycleBaseUri; }
    public Duration requestTimeout() { return requestTimeout; }
    public String requiredProtocolVersion() { return requiredProtocolVersion; }
    public RuntimeAttestation runtimeAttestation() { return runtimeAttestation; }

    String apiKey() { return apiKey; }
    String execdAccessToken() { return execdAccessToken; }

    @Override
    public String toString() {
        return "OpenSandboxConfig[lifecycleBaseUri=" + lifecycleBaseUri
                + ", apiKey=<redacted>, execdAccessToken=<redacted>, requestTimeout=" + requestTimeout
                + ", requiredProtocolVersion=" + requiredProtocolVersion + "]";
    }

    private static String secret(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > 4096 || value.chars().anyMatch(c -> c < 0x21 || c == 0x7f)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}
