package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.worker.WorkerCapability;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Optional on-disk escape-suite attestation hook for MVP-6 scaffolding.
 * Presence alone never opens VERIFIED; {@link VerifiedStatusGate} remains fail-closed
 * until a future release wires end-to-end attestation + escape suite.
 */
public final class EscapeSuiteAttestation {
    public static final String ENV_PATH = "VEYRION_ESCAPE_ATTESTATION_PATH";
    private static final Duration MAX_AGE = Duration.ofDays(30);

    private EscapeSuiteAttestation() {
    }

    public record AttestationView(
            boolean present,
            boolean fresh,
            WorkerCapability capability,
            String attestationRef,
            String reasonCode
    ) {
    }

    public static AttestationView load(Instant now) {
        Objects.requireNonNull(now, "now");
        String configured = System.getenv(ENV_PATH);
        if (configured == null || configured.isBlank()) {
            configured = System.getProperty("veyrion.escape.attestation.path", "");
        }
        if (configured == null || configured.isBlank()) {
            return new AttestationView(false, false, null, "", "ATTESTATION_PATH_UNSET");
        }
        Path path = Path.of(configured);
        if (!Files.isRegularFile(path)) {
            return new AttestationView(false, false, null, "", "ATTESTATION_FILE_MISSING");
        }
        try {
            Instant modified = Files.getLastModifiedTime(path).toInstant();
            boolean fresh = !modified.isAfter(now) && !modified.isBefore(now.minus(MAX_AGE));
            String text = Files.readString(path);
            WorkerCapability capability = null;
            if (text.toUpperCase().contains("GVISOR")) capability = WorkerCapability.HARDENED_GVISOR;
            else if (text.toUpperCase().contains("KATA")) capability = WorkerCapability.HARDENED_KATA;
            String ref = "file:" + path.getFileName();
            if (!fresh) {
                return new AttestationView(true, false, capability, ref, "ATTESTATION_STALE");
            }
            if (capability == null) {
                return new AttestationView(true, true, null, ref, "ATTESTATION_CAPABILITY_UNKNOWN");
            }
            if (!text.toUpperCase().contains("SANDBOX_ESCAPE_SUITE_PASSED")) {
                return new AttestationView(true, true, capability, ref, "ESCAPE_SUITE_NOT_MARKED_PASSED");
            }
            return new AttestationView(true, true, capability, ref, "ATTESTATION_PRESENT_BUT_GATE_CLOSED");
        } catch (Exception ex) {
            return new AttestationView(false, false, null, "", "ATTESTATION_READ_FAILED");
        }
    }
}
