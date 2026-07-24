package com.aq.jvmsentinel.sandbox;

import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.util.List;
import java.util.Objects;

/** Safe creation request: the public shape intentionally has no host mounts, environment, or credentials. */
public record SandboxRequest(String image, List<String> entrypoint, int timeoutSeconds,
                             ResourceBudget resourceBudget, boolean fixtureOnly,
                             WorkerCapability requiredCapability) {
    public SandboxRequest {
        image = SandboxContracts.text(image, "image", 2048);
        entrypoint = SandboxContracts.command(entrypoint, "entrypoint");
        Objects.requireNonNull(resourceBudget, "resourceBudget");
        Objects.requireNonNull(requiredCapability, "requiredCapability");
        if (timeoutSeconds < 60 || timeoutSeconds > 86_400
                || timeoutSeconds > resourceBudget.maxWallClockSeconds()) {
            throw new IllegalArgumentException("timeoutSeconds is outside the resource budget");
        }
        if (requiredCapability == WorkerCapability.STATIC_ONLY) {
            throw new IllegalArgumentException("STATIC_ONLY cannot create a sandbox");
        }
        if (!fixtureOnly && requiredCapability != WorkerCapability.HARDENED_GVISOR
                && requiredCapability != WorkerCapability.HARDENED_KATA) {
            throw new IllegalArgumentException("external artifacts require a hardened runtime");
        }
        if (requiredCapability == WorkerCapability.FIXTURE_RUNC && !fixtureOnly) {
            throw new IllegalArgumentException("FIXTURE_RUNC is restricted to trusted fixtures");
        }
    }
}
